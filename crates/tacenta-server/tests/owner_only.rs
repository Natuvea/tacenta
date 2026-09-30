//! The data directory and the snapshot files in it are owner-only.
//!
//! **Why these tests start the server binary under `umask 000`.** The mode a
//! new file or directory gets is the mode the program asks for with the
//! process umask's bits cleared. Under the usual `022` a program that asks for
//! nothing in particular gets `0644` files and `0755` directories, and under
//! `077` it gets owner-only ones, so a test run in-process passes or fails with
//! whatever umask the developer's shell happens to have. Starting the server
//! under `umask 000` removes that: a file made without an explicit mode is
//! `0666` and a directory `0777`, so a `0600`/`0700` can only have come from
//! the server asking for it. Each test also has the shell create a probe file
//! before it starts the server, and checks the probe came out `0666`, so a
//! umask that did not take effect fails the test instead of passing it.

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rand::{RngCore as _, TryRngCore as _};
use tacenta_server::{Config, Server};

fn scratch_dir() -> PathBuf {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    std::env::temp_dir().join(format!("tacenta-owner-only-{}", u64::from_le_bytes(b)))
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn config(data_dir: &Path) -> Config {
    Config {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: Some(data_dir.to_path_buf()),
        tls: None,
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    }
}

/// Run the server binary under `umask 000`, stop it with SIGTERM once it is
/// serving, and wait for it to exit having written its shutdown snapshot. The
/// shell makes `probe` first, to show the umask took effect.
fn run_server_under_open_umask(data_dir: &Path, probe: &Path) {
    let mut child = Command::new("sh")
        .arg("-c")
        // `$0` is the binary, `$1` the probe. `exec` keeps the pid, so the
        // signal below reaches the server and not a shell around it.
        .arg(r#"umask 000; : > "$1"; exec "$0""#)
        .arg(env!("CARGO_BIN_EXE_tacenta-server"))
        .arg(probe)
        .env("TACENTA_BIND", "127.0.0.1")
        .env("TACENTA_DIRECTORY_PORT", "0")
        .env("TACENTA_RELAY_PORT", "0")
        .env("TACENTA_ACCOUNTS_PORT", "0")
        .env("TACENTA_PROVISIONING_PORT", "0")
        .env("TACENTA_DATA_DIR", data_dir)
        .env_remove("TACENTA_DATABASE_URL")
        .env_remove("TACENTA_TLS_CERT")
        .env_remove("TACENTA_TLS_KEY")
        .env_remove("TACENTA_SNAPSHOT_SECS")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the server binary should start");

    // Long enough for all four listeners to bind and the signal handler to be
    // installed, as in tests/sigterm.rs.
    std::thread::sleep(Duration::from_millis(1500));
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill should be available on a unix host");
    assert!(status.success());

    // The shutdown snapshot is written before the process exits, so waiting for
    // the exit waits for all three files.
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            panic!("the server did not exit after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(mode(probe), 0o666, "the umask was not relaxed to 000");
}

fn assert_snapshots_owner_only(data_dir: &Path) {
    for name in ["directory.snapshot", "relay.snapshot", "accounts.snapshot"] {
        let file = data_dir.join(name);
        assert!(file.exists(), "{name} was not written");
        assert_eq!(mode(&file), 0o600, "{name}");
    }
    let mut names: Vec<String> = std::fs::read_dir(data_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["accounts.snapshot", "directory.snapshot", "relay.snapshot"],
        "nothing but the snapshots should be left in the data directory"
    );
}

/// A data directory the server creates is `0700`, and the files it writes
/// there are `0600`, when the umask would allow anyone to read them.
#[test]
fn a_new_data_directory_and_its_snapshots_are_owner_only() {
    let base = scratch_dir();
    std::fs::create_dir_all(&base).unwrap();
    let data_dir = base.join("data");
    let probe = base.join("probe");

    run_server_under_open_umask(&data_dir, &probe);

    assert_eq!(mode(&data_dir), 0o700);
    assert_snapshots_owner_only(&data_dir);
    std::fs::remove_dir_all(&base).ok();
}

/// A directory that already exists keeps the mode it has: the server does not
/// change it. Snapshot files that exist with a wide mode are replaced by
/// `0600` ones the next time the server writes them.
#[tokio::test]
async fn an_existing_directory_keeps_its_mode_and_its_files_are_tightened() {
    let base = scratch_dir();
    std::fs::create_dir_all(&base).unwrap();
    let data_dir = base.join("data");
    let probe = base.join("probe");

    // Snapshots as an earlier version could have left them: valid, and
    // with a wide mode, in a directory the operator made `0755`.
    let seed = Server::bind(&config(&data_dir)).await.unwrap();
    seed.persist().unwrap();
    drop(seed);
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    for name in ["directory.snapshot", "relay.snapshot", "accounts.snapshot"] {
        std::fs::set_permissions(data_dir.join(name), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    }
    run_server_under_open_umask(&data_dir, &probe);

    assert_eq!(mode(&data_dir), 0o755, "an existing directory was changed");
    assert_snapshots_owner_only(&data_dir);
    std::fs::remove_dir_all(&base).ok();
}
