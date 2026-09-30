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

/// Write the identity secret to a new file that only its owner can open.
///
/// The bytes carry a private key, so the file is created with mode `0600` in
/// the `open` call itself (on Unix, whatever the umask): there is no moment at
/// which it exists with wider access. It must not already exist; a file or a
/// symbolic link found at `path` is an error rather than something to write
/// through. On other platforms the file gets the platform's default access.
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    create_secret_file(path)?.write_all(bytes)
}

/// Create `path` as a new, empty file that only its owner can open.
fn create_secret_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    const CHILD_DIR: &str = "TACENTA_ECHO_TEST_DIR";

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tacenta-echo-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Runs only under [`the_secret_file_is_owner_only_whatever_the_umask`],
    /// which starts it under `umask 000`.
    #[test]
    #[ignore = "started by the_secret_file_is_owner_only_whatever_the_umask under umask 000"]
    fn secret_child() {
        let dir = PathBuf::from(std::env::var_os(CHILD_DIR).expect("run by the parent test"));
        // What a plain create yields under this umask, so the parent can check
        // the relaxed umask took effect and its `0600` is not vacuous.
        std::fs::File::create(dir.join("probe")).unwrap();
        // Created and left empty: this is the file as it is the instant it
        // exists, before anything is written to it or its mode is changed.
        drop(create_secret_file(&dir.join("empty")).unwrap());
        write_secret(&dir.join("written"), b"the secret").unwrap();
    }

    /// The identity secret is `0600` from the moment the file exists, not after
    /// a later `chmod`, whatever the umask.
    #[test]
    fn the_secret_file_is_owner_only_whatever_the_umask() {
        let dir = tempdir();
        let child = format!(
            "{}::secret_child",
            module_path!().split_once("::").unwrap().1
        );
        let out = Command::new("sh")
            .arg("-c")
            .arg(r#"umask 000; exec "$0" --exact "$1" --ignored"#)
            .arg(std::env::current_exe().unwrap())
            .arg(&child)
            .env(CHILD_DIR, &dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert_eq!(mode(&dir.join("probe")), 0o666, "the umask was not relaxed");
        assert_eq!(mode(&dir.join("empty")), 0o600);
        assert_eq!(mode(&dir.join("written")), 0o600);
        assert_eq!(std::fs::read(dir.join("written")).unwrap(), b"the secret");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A file already at the path is not overwritten, and a link is not
    /// followed: the identity is written once, to a file this call made.
    #[test]
    fn an_existing_file_or_link_is_refused_and_left_as_it_was() {
        let dir = tempdir();
        let existing = dir.join("existing");
        std::fs::write(&existing, b"already here").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&existing, &link).unwrap();
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();

        for path in [&existing, &link, &dangling] {
            let err = write_secret(path, b"the secret").unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        }

        assert_eq!(std::fs::read(&existing).unwrap(), b"already here");
        assert!(!dir.join("nowhere").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
