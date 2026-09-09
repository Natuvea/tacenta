//! The server persists when the process is asked to stop the way a container
//! stops it.
//!
//! **Why this test spawns a process instead of calling a function.** Every
//! other persistence test drives shutdown through `serve_until`, handing it a
//! future that resolves on demand. That covers what happens *after* the
//! shutdown signal and is blind to which signals produce one. `ctrl_c()`
//! alone is SIGINT, while a container runtime stops a process with SIGTERM;
//! a `shutdown_signal` that missed SIGTERM would pass every in-process test
//! and never write the snapshot in production.
//!
//! The only way to cover that is to run the actual binary and signal it.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rand::{RngCore as _, TryRngCore as _};

fn scratch_dir() -> PathBuf {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    std::env::temp_dir().join(format!("tacenta-sigterm-{}", u64::from_le_bytes(b)))
}

/// Send a signal by name using `kill`, so the test needs no libc dependency.
fn signal(pid: u32, sig: &str) {
    let status = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .expect("kill should be available on a unix host");
    assert!(status.success(), "kill -{sig} {pid} failed");
}

/// Wait for `path` to appear, up to `limit`.
fn wait_for(path: &Path, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn sigterm_writes_the_shutdown_snapshot() {
    let data_dir = scratch_dir();
    std::fs::create_dir_all(&data_dir).unwrap();

    // Port 0 everywhere: the OS picks, so concurrent test runs cannot collide
    // and the fixed 4720-4723 defaults are not required to be free.
    let mut child = Command::new(env!("CARGO_BIN_EXE_tacenta-server"))
        .env("TACENTA_BIND", "127.0.0.1")
        .env("TACENTA_DIRECTORY_PORT", "0")
        .env("TACENTA_RELAY_PORT", "0")
        .env("TACENTA_ACCOUNTS_PORT", "0")
        .env("TACENTA_PROVISIONING_PORT", "0")
        .env("TACENTA_DATA_DIR", &data_dir)
        .env_remove("TACENTA_DATABASE_URL")
        .env_remove("TACENTA_TLS_CERT")
        .env_remove("TACENTA_TLS_KEY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the server binary should start");

    // Give it time to bind all four listeners before signalling.
    std::thread::sleep(Duration::from_millis(1500));

    let snapshot = data_dir.join("relay.snapshot");
    assert!(
        !snapshot.exists(),
        "nothing should be written before shutdown -- if this fires the test is \
         proving the periodic snapshot, not the shutdown one"
    );

    signal(child.id(), "TERM");

    let wrote = wait_for(&snapshot, Duration::from_secs(10));
    let _ = child.wait();

    assert!(
        wrote,
        "SIGTERM must run the graceful shutdown and write a snapshot. \
         A service manager stops the process with SIGTERM, so a server that \
         handled only SIGINT would lose its state on every restart."
    );

    std::fs::remove_dir_all(&data_dir).ok();
}

#[test]
fn sigint_still_writes_the_shutdown_snapshot() {
    // Kept alongside SIGTERM so that handling one signal cannot cost the
    // one Ctrl-C sends.
    let data_dir = scratch_dir();
    std::fs::create_dir_all(&data_dir).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_tacenta-server"))
        .env("TACENTA_BIND", "127.0.0.1")
        .env("TACENTA_DIRECTORY_PORT", "0")
        .env("TACENTA_RELAY_PORT", "0")
        .env("TACENTA_ACCOUNTS_PORT", "0")
        .env("TACENTA_PROVISIONING_PORT", "0")
        .env("TACENTA_DATA_DIR", &data_dir)
        .env_remove("TACENTA_DATABASE_URL")
        .env_remove("TACENTA_TLS_CERT")
        .env_remove("TACENTA_TLS_KEY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the server binary should start");

    std::thread::sleep(Duration::from_millis(1500));
    signal(child.id(), "INT");

    let wrote = wait_for(&data_dir.join("relay.snapshot"), Duration::from_secs(10));
    let _ = child.wait();

    assert!(wrote, "SIGINT must still write a snapshot");

    std::fs::remove_dir_all(&data_dir).ok();
}
