//! Accounts and sessions survive a restart: a tenant, its API key, its users,
//! and a live session token are snapshotted on shutdown and loaded on bind.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use rand::{RngCore as _, TryRngCore as _};
use tacenta_accounts::AccountResponse;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_server::{Config, Server};
use tacenta_transport::{AccountConnection, ProvisionConnection, ProvisionOutcome};

fn scratch_dir() -> PathBuf {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    std::env::temp_dir().join(format!(
        "tacenta-accounts-persist-{}",
        u64::from_le_bytes(b)
    ))
}

#[tokio::test]
async fn accounts_and_sessions_survive_a_restart() {
    let data_dir = scratch_dir();
    let config = Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: Some(data_dir.clone()),
        tls: None,
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    };

    // First run: a tenant, a user, and a signed-in session — then shut down,
    // which persists the account snapshot.
    let (api_key, token) = {
        let server = Server::bind(&config).await.unwrap();
        let accounts = server.accounts_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

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
        drop(acc);

        stop.send(()).unwrap();
        handle
            .await
            .unwrap()
            .expect("first server persists cleanly");
        (api_key, token)
    };

    // Second run: bind from the same data directory. Everything loaded.
    {
        let server = Server::bind(&config).await.unwrap();
        let accounts = server.accounts_addr().unwrap();
        let provisioning = server.provisioning_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let mut acc = AccountConnection::connect(accounts).await.unwrap();
        // The user survived: alice still signs in.
        assert!(matches!(
            acc.sign_in(&api_key, "alice", "hunter2!!").await.unwrap(),
            AccountResponse::SignedIn { .. }
        ));
        // The tenant and its API key survived: a new user can be created.
        assert_eq!(
            acc.sign_up_user(&api_key, "bob", "hunter2!!")
                .await
                .unwrap(),
            AccountResponse::UserCreated {
                username: "bob".into()
            },
        );

        // The session survived: the token from the *first* run still provisions
        // a device under alice's handle.
        let mut party =
            DefaultProvider::generate("acme/alice", 1, &mut rand::rngs::OsRng.unwrap_err())
                .unwrap();
        let bundle = party
            .publish_bundle(&mut rand::rngs::OsRng.unwrap_err())
            .await
            .unwrap();
        let identity = CryptoProvider::identity_key(&party);
        let bundle_bytes = bundle.clone();
        let mut prov = ProvisionConnection::connect(provisioning).await.unwrap();
        let outcome = prov
            .provision(&token, 1, identity, bundle_bytes, |ch| {
                party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
            })
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ProvisionOutcome::Provisioned {
                handle: "acme/alice".into()
            },
        );

        stop.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    std::fs::remove_dir_all(&data_dir).ok();
}
