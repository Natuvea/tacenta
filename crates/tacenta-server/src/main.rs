//! `cargo run -p tacenta-server` — bind the directory service and the
//! relay server over one shared directory and serve until interrupted.
//!
//! Configuration is read from the environment, all optional:
//!
//! - `TACENTA_BIND` — bind address (default `127.0.0.1`)
//! - `TACENTA_DIRECTORY_PORT` — directory service port (default `4720`)
//! - `TACENTA_RELAY_PORT` — relay server port (default `4721`)
//! - `TACENTA_ACCOUNTS_PORT` — account service port (default `4722`)
//! - `TACENTA_PROVISIONING_PORT` — provisioning service port (default `4723`)
//! - `TACENTA_DATABASE_URL` — run accounts on this PostgreSQL (needs the
//!   `postgres` feature; default: none, in-memory snapshot store)
//! - `TACENTA_DATA_DIR` — persist state here across restarts (default: none,
//!   state is in memory only)
//! - `TACENTA_SNAPSHOT_SECS` — also snapshot on this interval, not only on
//!   shutdown (needs `TACENTA_DATA_DIR`; default: shutdown-only)
//! - `TACENTA_TLS_CERT` / `TACENTA_TLS_KEY` — PEM certificate and PKCS#8 key;
//!   set both to serve TLS (default: none, plaintext TCP)
//!
//! A client points its directory connection at the directory address and
//! its relay connection at the relay address.

use std::net::IpAddr;
use std::path::PathBuf;
use tacenta_server::{Config, RegistrationPolicy, Server, TlsFiles};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = config_from_env();
    let server = Server::bind(&config).await?;
    let scheme = if server.is_tls() {
        "TLS"
    } else {
        "plaintext TCP"
    };
    println!("tacenta-server ({scheme})");
    println!("  directory service  {}", server.directory_addr()?);
    println!("  relay server       {}", server.relay_addr()?);
    println!("  account service    {}", server.accounts_addr()?);
    println!("  provisioning       {}", server.provisioning_addr()?);
    match (&config.data_dir, config.snapshot_interval) {
        (Some(dir), Some(period)) => println!(
            "  persisting state to {} (every {}s and on SIGINT/SIGTERM)",
            dir.display(),
            period.as_secs()
        ),
        (Some(dir), None) => println!(
            "  persisting state to {} (saved on SIGINT/SIGTERM)",
            dir.display()
        ),
        (None, _) => println!("  state is in memory only (set TACENTA_DATA_DIR to persist)"),
    }
    server.serve().await
}

/// Read [`Config`] from the environment, falling back to defaults. An
/// unparseable value is ignored in favour of the default rather than
/// aborting startup.
fn config_from_env() -> Config {
    let mut config = Config::default();
    if let Some(bind) = std::env::var("TACENTA_BIND")
        .ok()
        .and_then(|v| v.parse::<IpAddr>().ok())
    {
        config.bind = bind;
    }
    if let Some(port) = std::env::var("TACENTA_DIRECTORY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        config.directory_port = port;
    }
    if let Some(port) = std::env::var("TACENTA_RELAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        config.relay_port = port;
    }
    if let Some(port) = std::env::var("TACENTA_ACCOUNTS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        config.accounts_port = port;
    }
    if let Some(port) = std::env::var("TACENTA_PROVISIONING_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        config.provisioning_port = port;
    }
    if let Ok(url) = std::env::var("TACENTA_DATABASE_URL") {
        config.database_url = Some(url);
    }
    if let Some(dir) = std::env::var_os("TACENTA_DATA_DIR") {
        config.data_dir = Some(PathBuf::from(dir));
    }
    if let Some(secs) = std::env::var("TACENTA_SNAPSHOT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
    {
        config.snapshot_interval = Some(std::time::Duration::from_secs(secs));
    }
    // The relay's whole-node memory ceiling, in bytes; unset uses the built-in
    // default. Set this from the node's RAM on a public self-service listener.
    if let Some(bytes) = std::env::var("TACENTA_RELAY_MAX_TOTAL_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|b| *b > 0)
    {
        config.relay_max_total_bytes = Some(bytes);
    }
    // New handle registrations allowed per source IP per hour ; unset uses
    // the built-in default. Raise it for NAT headroom.
    if let Some(n) = std::env::var("TACENTA_REGISTRATION_MAX_PER_HOUR")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        config.registration_max_per_hour = Some(n);
    }
    // The per-listener connection cap; unset uses the built-in default.
    // Set it below the node's file-descriptor budget on a public listener.
    if let Some(n) = std::env::var("TACENTA_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        config.max_connections = Some(n);
    }
    // Registration policy (layer 2): `accounts-only` closes unauthenticated
    // self-registration; anything else (or unset) is the open default.
    if let Ok(policy) = std::env::var("TACENTA_REGISTRATION_POLICY") {
        config.registration_policy = match policy.trim().to_ascii_lowercase().as_str() {
            "accounts-only" | "accounts_only" => Some(RegistrationPolicy::AccountsOnly),
            _ => Some(RegistrationPolicy::Open),
        };
    }
    // TLS needs both a certificate and a key; set both or neither.
    if let (Some(cert), Some(key)) = (
        std::env::var_os("TACENTA_TLS_CERT"),
        std::env::var_os("TACENTA_TLS_KEY"),
    ) {
        config.tls = Some(TlsFiles {
            cert_pem: PathBuf::from(cert),
            key_pem: PathBuf::from(key),
        });
    }
    config
}
