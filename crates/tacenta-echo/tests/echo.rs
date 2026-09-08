//! The echo bot echoes, and keeps its identity across a restart — the two
//! properties that make it a real reference agent rather than a demo prop.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tacenta_client::{Config, DefaultClient};
use tacenta_echo::EchoBot;
use tacenta_server::{Config as ServerConfig, Server};

async fn start_server() -> (SocketAddr, SocketAddr) {
    let server = Server::bind(&ServerConfig {
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
    let directory = server.directory_addr().unwrap();
    let relay = server.relay_addr().unwrap();
    tokio::spawn(server.serve());
    (directory, relay)
}

fn config(directory: SocketAddr, relay: SocketAddr, user: &str) -> Config {
    Config {
        directory,
        relay,
        user: user.into(),
        device: 1,
    }
}

#[tokio::test]
async fn the_bot_echoes_a_message_back() {
    let (directory, relay) = start_server().await;
    let mut bot = EchoBot::connect(&config(directory, relay, "+echo"))
        .await
        .unwrap();
    let bot_addr = bot.address().clone();

    let mut alice = DefaultClient::connect(&config(directory, relay, "+alice"))
        .await
        .unwrap();
    let alice_addr = alice.address().clone();

    // Alice sends the bot a message; the bot receives and echoes it in one
    // batch; Alice gets her own bytes back, attributed to the bot.
    alice.send(&bot_addr, b"hello, echo").await.unwrap();
    assert_eq!(bot.serve_once().await.unwrap(), 1);
    let back = alice.receive().await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].from, bot_addr);
    assert_eq!(back[0].plaintext, b"hello, echo");

    // The bot echoed to Alice's address, not some fabricated one.
    assert_ne!(bot_addr, alice_addr);
}

#[tokio::test]
async fn the_bot_keeps_its_identity_across_a_restart() {
    let (directory, relay) = start_server().await;

    // First run: the bot enrols and saves its identity.
    let bot = EchoBot::connect(&config(directory, relay, "+echo"))
        .await
        .unwrap();
    let addr = bot.address().clone();
    let saved = bot.export_identity();
    drop(bot);

    // Restart: reconnect under the saved identity — same address, same bound
    // key (a fresh identity would be refused for the already-bound address).
    let mut bot = EchoBot::connect_with_identity(&config(directory, relay, "+echo"), &saved)
        .await
        .unwrap();
    assert_eq!(bot.address(), &addr);

    // And it still echoes: a peer reaches the same bot after the restart.
    let mut alice = DefaultClient::connect(&config(directory, relay, "+alice"))
        .await
        .unwrap();
    alice.send(&addr, b"still here?").await.unwrap();
    assert_eq!(bot.serve_once().await.unwrap(), 1);
    let back = alice.receive().await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].plaintext, b"still here?");
}
