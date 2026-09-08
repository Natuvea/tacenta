//! End-to-end device provisioning against the running server: a user signs up,
//! signs in for a session token, and provisions a device — binding its identity
//! into the directory under the account's handle `acme/alice`, after which the
//! handle resolves in the directory. Plus the refusals: a bad session token,
//! and a second identity trying to claim the same handle.

use std::net::{IpAddr, Ipv4Addr};

use rand::TryRngCore as _;
use tacenta_accounts::AccountResponse;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::DeviceAddr;
use tacenta_server::{Config, Server};
use tacenta_transport::{AccountConnection, DirConnection, ProvisionConnection, ProvisionOutcome};

fn sign(party: &DefaultProvider, challenge: &[u8]) -> Vec<u8> {
    party.sign_challenge(challenge, &mut rand::rngs::OsRng.unwrap_err())
}

async fn material(party: &mut DefaultProvider) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = CryptoProvider::publish_bundle(party, &mut rng)
        .await
        .unwrap();
    (CryptoProvider::identity_key(party), bundle)
}

#[tokio::test]
async fn a_signed_in_user_provisions_a_device_under_its_handle() {
    let server = Server::bind(&Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
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
    let accounts_addr = server.accounts_addr().unwrap();
    let provisioning_addr = server.provisioning_addr().unwrap();
    let directory_addr = server.directory_addr().unwrap();
    tokio::spawn(server.serve());

    // Sign up a tenant and a user, then sign in for a session token.
    let mut acc = AccountConnection::connect(accounts_addr).await.unwrap();
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

    // Provision a device identity under the session.
    let mut party =
        DefaultProvider::generate("acme/alice", 1, &mut rand::rngs::OsRng.unwrap_err()).unwrap();
    let (identity, bundle) = material(&mut party).await;
    let mut prov = ProvisionConnection::connect(provisioning_addr)
        .await
        .unwrap();
    let outcome = prov
        .provision(&token, 1, identity.clone(), bundle, |c| sign(&party, c))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ProvisionOutcome::Provisioned {
            handle: "acme/alice".into()
        },
    );

    // The directory now resolves the account's handle to that identity.
    let mut dir = DirConnection::connect(directory_addr).await.unwrap();
    let DirResponse::Found {
        identity: found, ..
    } = dir.lookup(&DeviceAddr::new("acme/alice", 1)).await.unwrap()
    else {
        panic!("the handle should be bound");
    };
    assert_eq!(found, identity, "the handle holds the provisioned identity");

    // A bad session token cannot provision (checked before anything else).
    let mut prov2 = ProvisionConnection::connect(provisioning_addr)
        .await
        .unwrap();
    let bad = prov2
        .provision("ses_bogus", 2, vec![1, 2, 3], vec![4, 5, 6], |_| {
            vec![0u8; 64]
        })
        .await
        .unwrap();
    assert_eq!(bad, ProvisionOutcome::BadSession);

    // A different identity cannot claim the same handle — trust on first use.
    let mut other =
        DefaultProvider::generate("acme/alice", 1, &mut rand::rngs::OsRng.unwrap_err()).unwrap();
    let (other_identity, other_bundle) = material(&mut other).await;
    let mut prov3 = ProvisionConnection::connect(provisioning_addr)
        .await
        .unwrap();
    let rejected = prov3
        .provision(&token, 1, other_identity, other_bundle, |c| sign(&other, c))
        .await
        .unwrap();
    assert_eq!(rejected, ProvisionOutcome::Rejected);
}
