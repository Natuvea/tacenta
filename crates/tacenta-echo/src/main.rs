//! Runnable echo bot. Connects to a Tacenta server and echoes every message
//! back to its sender, keeping its identity across restarts.
//!
//! Configuration comes from the environment, all optional:
//!
//! - `TACENTA_DIRECTORY` — directory service address (default `127.0.0.1:4720`)
//! - `TACENTA_RELAY` — relay server address (default `127.0.0.1:4721`)
//! - `TACENTA_ECHO_USER` — the bot's user identifier (default `+echo`)
//! - `TACENTA_ECHO_DEVICE` — the bot's device number (default `1`)
//! - `TACENTA_ECHO_IDENTITY` — a file to persist the bot's identity secret in.
//!   Written on first run and read on later runs, so the bot keeps the same
//!   bound key. Without it the bot generates a fresh identity each run and
//!   cannot re-bind an address it already registered.
//!
//! Account mode — set `TACENTA_API_KEY` to run as a tenant user
//! (`<tenant>/<username>`) so any user in the tenant can `find` and message the
//! bot (the path the quickstart uses):
//!
//! - `TACENTA_API_KEY` — the tenant API key (enables account mode).
//! - `TACENTA_ECHO_PASSWORD` — the echo user's password (required).
//! - `TACENTA_ECHO_USERNAME` — the echo user's username (default `echo`).
//! - `TACENTA_ACCOUNTS` — account service address (default `127.0.0.1:4722`).
//! - `TACENTA_PROVISIONING` — provisioning address (default `127.0.0.1:4723`).

use std::path::{Path, PathBuf};

use std::net::{SocketAddr, ToSocketAddrs};
use tacenta_client::{AccountConfig, Config, DefaultClient};
use tacenta_echo::EchoBot;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Write the identity secret, restricting it to the owner where the platform
/// supports it. The bytes carry a private key.
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Account mode: with a tenant API key set, the bot signs in as a tenant
    // user (e.g. `acme/echo`) so any user in the tenant can `find("echo")` and
    // message it. This is the path the quickstart uses. Without an API key it
    // falls back to the device-level `+echo` address.
    if let Ok(api_key) = std::env::var("TACENTA_API_KEY") {
        return run_account_mode(api_key).await;
    }

    let config = Config {
        directory: env_or("TACENTA_DIRECTORY", "127.0.0.1:4720").parse()?,
        relay: env_or("TACENTA_RELAY", "127.0.0.1:4721").parse()?,
        user: env_or("TACENTA_ECHO_USER", "+echo"),
        device: env_or("TACENTA_ECHO_DEVICE", "1").parse()?,
    };
    let identity_path = std::env::var("TACENTA_ECHO_IDENTITY")
        .ok()
        .map(PathBuf::from);

    let mut bot = match identity_path.as_deref() {
        // A saved identity: reconnect under the same bound key.
        Some(path) if path.exists() => {
            let saved = std::fs::read(path)?;
            EchoBot::connect_with_identity(&config, &saved).await?
        }
        // First run: enrol with a fresh identity, and persist it if asked.
        _ => {
            let bot = EchoBot::connect(&config).await?;
            if let Some(path) = identity_path.as_deref() {
                write_secret(path, &bot.export_identity())?;
            }
            bot
        }
    };

    println!(
        "echo bot online as {} (device {})",
        bot.address().user,
        bot.address().device
    );
    bot.serve().await?;
    Ok(())
}

/// Run as a tenant user (`<tenant>/<username>`) so any user in the tenant can
/// `find` and message the bot. Reads the account service addresses and the
/// echo user's credentials from the environment.
async fn run_account_mode(api_key: String) -> Result<(), Box<dyn std::error::Error>> {
    let accounts = resolve(&env_or("TACENTA_ACCOUNTS", "127.0.0.1:4722"))?;
    let config = AccountConfig {
        directory: resolve(&env_or("TACENTA_DIRECTORY", "127.0.0.1:4720"))?,
        relay: resolve(&env_or("TACENTA_RELAY", "127.0.0.1:4721"))?,
        accounts,
        provisioning: resolve(&env_or("TACENTA_PROVISIONING", "127.0.0.1:4723"))?,
        api_key,
        identifier: env_or("TACENTA_ECHO_USERNAME", "echo"),
        password: std::env::var("TACENTA_ECHO_PASSWORD")
            .map_err(|_| "TACENTA_ECHO_PASSWORD is required in account mode")?,
        device: env_or("TACENTA_ECHO_DEVICE", "1").parse()?,
    };

    // With TACENTA_SERVER_NAME set, connect over TLS validating that name (the
    // server's certificate), even though the address resolves to an internal
    // host — rustls checks the certificate against the name, not the IP.
    let tls = std::env::var("TACENTA_SERVER_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|name| (name, tacenta_client::ClientTls::web_pki()));

    // Create the echo user if it does not exist yet. A taken username means it
    // already does — fine, we sign in next either way.
    let signup = match &tls {
        Some((name, t)) => {
            DefaultClient::sign_up_tls(
                accounts,
                name,
                t,
                &config.api_key,
                &config.identifier,
                &config.password,
            )
            .await
        }
        None => {
            DefaultClient::sign_up(
                accounts,
                &config.api_key,
                &config.identifier,
                &config.password,
            )
            .await
        }
    };
    if let Err(e) = signup {
        eprintln!(
            "echo: sign_up returned {e:?} — continuing to sign in (the account may already exist)"
        );
    }

    let mut bot = match &tls {
        Some((name, t)) => EchoBot::sign_in_tls(&config, name, t).await?,
        None => EchoBot::sign_in(&config).await?,
    };
    println!("echo bot online as {}", bot.address().user);
    bot.serve().await?;
    Ok(())
}

/// Resolve a `host:port` (an internal host name, or an IP) to a socket
/// address.
fn resolve(host_port: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    host_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("cannot resolve {host_port}").into())
}
