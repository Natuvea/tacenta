//! The server running accounts on PostgreSQL: sign up, sign in, and provision
//! a device, then confirm the handle resolves in the directory — the same flow
//! as the in-memory server test, but with `database_url` set. Runs only when
//! `TACENTA_TEST_DATABASE_URL` is set (and the `postgres` feature is on).
#![cfg(feature = "postgres")]

use std::net::{IpAddr, Ipv4Addr};

use rand::TryRngCore as _;
use tacenta_accounts::AccountResponse;
use tacenta_accounts::pg::PgAccounts;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::DeviceAddr;
use tacenta_server::{Config, Server};
use tacenta_transport::{AccountConnection, DirConnection, ProvisionConnection, ProvisionOutcome};

#[tokio::test]
async fn the_server_runs_accounts_on_postgres() {
    let Ok(url) = std::env::var("TACENTA_TEST_DATABASE_URL") else {
        eprintln!("skipping: set TACENTA_TEST_DATABASE_URL to run the Postgres server test");
        return;
    };

    // Clean slate before the server binds.
    let pg = PgAccounts::connect(&url).await.unwrap();
    pg.migrate().await.unwrap();
    pg.truncate().await.unwrap();
    drop(pg);

    let server = Server::bind(&Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: Some(url),
        data_dir: None,
        tls: None,
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    })
    .await
    .unwrap();
    let accounts = server.accounts_addr().unwrap();
    let provisioning = server.provisioning_addr().unwrap();
    let directory = server.directory_addr().unwrap();
    tokio::spawn(server.serve());

    // Sign up a tenant and a user, then sign in — all against Postgres.
    let mut acc = AccountConnection::connect(accounts).await.unwrap();
    let AccountResponse::TenantCreated { api_key, .. } = acc
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };
    acc.sign_up_user(&api_key, "alice", "hunter2!!")
        .await
        .unwrap();
    let AccountResponse::SignedIn { token, .. } =
        acc.sign_in(&api_key, "alice", "hunter2!!").await.unwrap()
    else {
        panic!("expected a session token");
    };

    // Provision alice's device — the provisioner validates the session against
    // Postgres, then binds the handle into the (in-memory) directory.
    let mut party =
        DefaultProvider::generate("acme/alice", 1, &mut rand::rngs::OsRng.unwrap_err()).unwrap();
    let bundle = party
        .publish_bundle(&mut rand::rngs::OsRng.unwrap_err())
        .await
        .unwrap();
    let identity = CryptoProvider::identity_key(&party);
    let bundle_bytes = bundle.clone();
    let mut prov = ProvisionConnection::connect(provisioning).await.unwrap();
    let outcome = prov
        .provision(&token, 1, identity.clone(), bundle_bytes, |c| {
            party.sign_challenge(c, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ProvisionOutcome::Provisioned {
            handle: "acme/alice".into()
        },
    );

    // The directory resolves the account's handle to the provisioned identity.
    let mut dir = DirConnection::connect(directory).await.unwrap();
    let DirResponse::Found {
        identity: found, ..
    } = dir.lookup(&DeviceAddr::new("acme/alice", 1)).await.unwrap()
    else {
        panic!("the handle should be bound");
    };
    assert_eq!(found, identity);
}
