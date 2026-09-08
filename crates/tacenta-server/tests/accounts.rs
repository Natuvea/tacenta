//! The running server serves the account endpoint alongside the directory and
//! relay: a client reaches `accounts_addr()` and signs up and in.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_accounts::AccountResponse;
use tacenta_server::{Config, Server};
use tacenta_transport::AccountConnection;

#[tokio::test]
async fn the_server_serves_the_account_endpoint() {
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
    let accounts = server.accounts_addr().unwrap();
    tokio::spawn(server.serve());

    let mut conn = AccountConnection::connect(accounts).await.unwrap();

    let AccountResponse::TenantCreated { api_key, .. } = conn
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant to be created");
    };
    assert_eq!(
        conn.sign_up_user(&api_key, "alice", "hunter2!!")
            .await
            .unwrap(),
        AccountResponse::UserCreated {
            username: "alice".into()
        },
    );
    let signed_in = conn.sign_in(&api_key, "alice", "hunter2!!").await.unwrap();
    assert!(matches!(
        signed_in,
        AccountResponse::SignedIn { username, token } if username == "alice" && token.starts_with("ses_")
    ));
}
