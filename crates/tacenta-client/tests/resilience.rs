//! The client survives what production does to it. A server restart drops
//! every connection and queues mail in the meantime — send and receive
//! reconnect under the same identity and drain the backlog without waiting
//! for a push. A poison message — a frame that can never decrypt — is
//! acknowledged past and dropped, not allowed to wedge the queue.

use rand::{RngCore as _, TryRngCore as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tacenta_client::{
    Config as ClientConfig, DefaultClient, DeviceAddr, Error, ErrorKind, RestoreOutcome,
    SecureStore, SecureStoreError, SessionProvider,
};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::{Request, Response, decode_response, encode_request};
use tacenta_server::{Config, Server};
use tacenta_transport::{Connection, DirConnection};
use tacenta_wire::{Envelope, Kind};

/// A unique temp directory for one test run.
fn scratch_dir() -> PathBuf {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut b);
    std::env::temp_dir().join(format!("tacenta-resilience-{}", u64::from_le_bytes(b)))
}

/// Bind and serve a server, returning its socket addresses and a stop
/// handle that persists state and waits for shutdown.
struct Running {
    directory: SocketAddr,
    relay: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Running {
    async fn start(config: &Config) -> Running {
        let server = Server::bind(config).await.unwrap();
        let directory = server.directory_addr().unwrap();
        let relay = server.relay_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));
        Running {
            directory,
            relay,
            stop,
            handle,
        }
    }

    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        self.handle.await.unwrap().expect("server persists cleanly");
    }
}

fn server_config(data_dir: &std::path::Path) -> Config {
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

fn client_config(running: &Running, user: &str) -> ClientConfig {
    ClientConfig {
        directory: running.directory,
        relay: running.relay,
        user: user.into(),
        device: 1,
    }
}

/// A server restart drops both clients' connections and the sender's next
/// messages queue while the receiver is away. The sender reconnects
/// transparently inside `send`; the receiver reconnects inside `receive`
/// and drains the whole backlog from the poll, not from a push.
#[tokio::test]
async fn backlog_drains_after_a_server_restart() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);

    let first = Running::start(&config).await;
    let mut alice = DefaultClient::connect(&client_config(&first, "+alice"))
        .await
        .unwrap();
    let mut bob = DefaultClient::connect(&client_config(&first, "+bob"))
        .await
        .unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    // Establish the session while the first server is up.
    alice.send(&bob_addr, b"one").await.unwrap();
    let got = bob.receive().await.unwrap();
    assert_eq!(got[0].plaintext, b"one");

    // Restart the server on the same ports (state persisted to disk).
    let (dir_port, relay_port) = (first.directory.port(), first.relay.port());
    first.shutdown().await;
    let mut config2 = server_config(&data_dir);
    config2.directory_port = dir_port;
    config2.relay_port = relay_port;
    let second = Running::start(&config2).await;

    // Alice's connection died with the first server; send reconnects under
    // her identity (the restarted directory still recognises it) and the
    // messages queue for the still-offline Bob.
    alice.send(&bob_addr, b"two").await.unwrap();
    alice.send(&bob_addr, b"three").await.unwrap();

    // Bob's receive finds its connection dead, reconnects, and drains the
    // backlog immediately — no push arrives for mail that queued before he
    // came back.
    let got = bob.receive().await.unwrap();
    let texts: Vec<&[u8]> = got.iter().map(|m| m.plaintext.as_slice()).collect();
    assert_eq!(texts, vec![b"two".as_slice(), b"three".as_slice()]);

    second.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A client that persists its full state and restarts as a *new process*
/// (fresh in-memory store, no live connection) resumes its conversation
/// mid-ratchet: a message the peer sent while it was down still decrypts.
/// This is what identity-only persistence could not do — a new store has
/// no session for the ciphertext, so it would fail to decrypt.
#[tokio::test]
async fn a_persisted_client_resumes_a_conversation_mid_ratchet() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);
    let bob_addr = DeviceAddr::new("+bob", 1);

    // A live conversation, ratchet advanced a few steps in both directions.
    alice.send(&bob_addr, b"one").await.unwrap();
    assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"one");
    bob.send(&alice_addr, b"two").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"two");

    // Bob persists his full state and "shuts down" (drop the process).
    let bob_state = bob.export_state().await.unwrap();
    drop(bob);

    // While Bob is down, Alice sends more — encrypted to the session Bob
    // just persisted, at ratchet positions a fresh store would not have.
    alice.send(&bob_addr, b"three").await.unwrap();
    alice.send(&bob_addr, b"four").await.unwrap();

    // Bob restarts from the saved state: a brand-new Client with a fresh
    // store, rehydrated from the blob. The queued messages decrypt.
    let mut bob = DefaultClient::connect_with_state(&client_config(&running, "+bob"), &bob_state)
        .await
        .unwrap();
    let got = bob.receive().await.unwrap();
    let texts: Vec<&[u8]> = got.iter().map(|m| m.plaintext.as_slice()).collect();
    assert_eq!(texts, vec![b"three".as_slice(), b"four".as_slice()]);

    // And the resumed session keeps ratcheting forward normally.
    bob.send(&alice_addr, b"five").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"five");

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A *first contact* — a message from a peer Bob has never spoken to — queued
/// while Bob is offline, then decrypted after Bob restores from exported
/// state.
///
/// This is the case that needs v3's prekey store in the blob. Carol's message is a PreKey message encrypted to one of Bob's
/// published one-time prekeys, and that prekey's private half lives only in
/// Bob's prekey store. Bob exports *before* Carol consumes it, so the private
/// half is in the blob; the directory only ever holds public halves. The
/// live-session test above cannot exercise this, because it needs a session
/// that does not yet exist.
#[tokio::test]
async fn first_contact_queued_while_offline_decrypts_after_restore() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    // Bob connects and publishes his bundle, but talks to no one yet.
    let bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    // He saves state and goes offline before any conversation exists.
    let bob_state = bob.export_state().await.unwrap();
    drop(bob);

    // Carol has never messaged Bob. Her first send establishes a new session
    // against his published bundle and queues while he is down.
    let mut carol = DefaultClient::connect(&client_config(&running, "+carol"))
        .await
        .unwrap();
    carol
        .send(&bob_addr, b"hello, first contact")
        .await
        .unwrap();

    // Bob restores from the saved state and must decrypt it. Before v3 this
    // failed: the fresh store had no private half for the consumed prekey.
    let mut bob = DefaultClient::connect_with_state(&client_config(&running, "+bob"), &bob_state)
        .await
        .unwrap();
    let got = bob.receive().await.unwrap();
    assert_eq!(
        got.iter()
            .map(|m| m.plaintext.as_slice())
            .collect::<Vec<_>>(),
        vec![b"hello, first contact".as_slice()],
        "the first-contact message must decrypt: its prekey private half is in the exported state"
    );

    // And the now-established session ratchets forward both ways.
    let carol_addr = DeviceAddr::new("+carol", 1);
    bob.send(&carol_addr, b"reply").await.unwrap();
    assert_eq!(carol.receive().await.unwrap()[0].plaintext, b"reply");

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Anchor A's detection mechanism (0078), exercised through an *explicit*
/// checkpoint: a state older than one the directory has already witnessed is
/// caught, and its sessions are discarded while the identity survives.
///
/// The anchor is the directory. Bob saves a state at generation 1, then does
/// more (generation 2) and checkpoints, so the directory's anchor moves to 2.
/// Restoring the *old* blob and calling `checkpoint` presents 1 against an
/// anchor of 2 — a rollback. This is anchor A working *when invoked*; it is not
/// auto-invoked on the default path (the presented generation is
/// unauthenticated, so it does not defend the file-rewriter this scenario
/// stages by hand — see the `#[ignore]`d forgery test), and it is detection
/// only until anchor B authenticates the generation.
#[tokio::test]
async fn a_rolled_back_state_is_detected_and_its_sessions_discarded() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut carol = DefaultClient::connect(&client_config(&running, "+carol"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);
    let carol_addr = DeviceAddr::new("+carol", 1);

    // Bob establishes a session with Alice — generation advances to 1.
    bob.send(&alice_addr, b"hi alice").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"hi alice");

    // Bob saves state now, at generation 1.
    let blob_old = bob.export_state().await.unwrap();

    // Bob advances — a session with Carol takes him to generation 2 — then
    // checkpoints, moving the directory's anchor to 2, ahead of the saved blob.
    bob.send(&carol_addr, b"hi carol").await.unwrap();
    assert_eq!(carol.receive().await.unwrap()[0].plaintext, b"hi carol");
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::Fresh);
    drop(bob);

    // Restore the OLD blob. Restore does not auto-checkpoint (anchor A is
    // opt-in, detection-only), so the sessions come back first...
    let mut bob = DefaultClient::connect_with_state(&client_config(&running, "+bob"), &blob_old)
        .await
        .unwrap();
    assert!(
        bob.has_open_session(&alice_addr),
        "restore itself carries the sessions; detection is a separate, opt-in step"
    );
    // ...and an explicit checkpoint presents generation 1 against an anchor of
    // 2 -> RolledBack -> sessions discarded, identity kept.
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::RolledBack);
    assert!(
        !bob.has_open_session(&alice_addr),
        "a rolled-back state, once checkpointed, discards the sessions it carried"
    );

    // The identity survives: Bob re-establishes with Alice and talks normally.
    bob.send(&alice_addr, b"fresh session").await.unwrap();
    assert_eq!(
        alice.receive().await.unwrap()[0].plaintext,
        b"fresh session"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// **The unsealed path's limit, documented.** Anchor A does not close the
/// rollback gap against a file-rewriting attacker, because the generation the
/// client presents is an unauthenticated plaintext `u64` at the tail of the
/// blob. An attacker who can write the state file — 0078's exact threat — writes
/// {old sessions, generation = u64::MAX}; the honest client presents MAX, the
/// directory answers Fresh, and the rewrite is not detected.
///
/// `#[ignore]`d because it asserts the *by-design* behaviour of the
/// **unsealed** path, to document its limit rather than to gate CI. This is
/// why the unsealed path makes no rollback claim and `connect_with_state`
/// does not auto-checkpoint. The closure is a *separate* path, not a change
/// to this one: `export_state_sealed` binds the generation under a
/// secure-storage key (0078 anchor B), and
/// `a_forged_sealed_generation_is_refused` asserts the same rewrite fails.
#[tokio::test]
#[ignore = "documents the unsealed path's limit: its generation is unauthenticated, so a rewritten file is not detected; the sealed path closes it"]
async fn a_forged_generation_defeats_rollback_detection() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut carol = DefaultClient::connect(&client_config(&running, "+carol"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);
    let carol_addr = DeviceAddr::new("+carol", 1);

    // Bob at generation 1, saves state carrying the Alice session.
    bob.send(&alice_addr, b"hi").await.unwrap();
    alice.receive().await.unwrap();
    let mut blob = bob.export_state().await.unwrap();

    // Bob advances to 2 and checkpoints, so the directory anchor is 2.
    bob.send(&carol_addr, b"hi").await.unwrap();
    carol.receive().await.unwrap();
    bob.checkpoint().await.unwrap();
    drop(bob);

    // Rewrite the trailing generation to u64::MAX in the old blob.
    let n = blob.len();
    blob[n - 8..].copy_from_slice(&u64::MAX.to_be_bytes());

    // Restore the forged blob and checkpoint: it presents u64::MAX -> Fresh, so
    // the sessions are NOT discarded even though this is a rolled-back state.
    let mut bob = DefaultClient::connect_with_state(&client_config(&running, "+bob"), &blob)
        .await
        .unwrap();
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::Fresh);
    assert!(
        bob.has_open_session(&alice_addr),
        "forged generation defeats detection: the rolled-back session survived"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Contrast: a *current* state restores Fresh and keeps its sessions, so the
/// rollback check does not fire on the ordinary restart it must not disturb.
#[tokio::test]
async fn a_current_state_restores_fresh_and_keeps_its_sessions() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);

    bob.send(&alice_addr, b"hi").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"hi");
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::Fresh);

    // Save at the current generation and restart from it. An explicit
    // checkpoint presents that generation against an equal anchor -> Fresh, and
    // the session stays: the detection does not fire on an ordinary restart.
    let blob = bob.export_state().await.unwrap();
    drop(bob);
    let mut bob = DefaultClient::connect_with_state(&client_config(&running, "+bob"), &blob)
        .await
        .unwrap();
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::Fresh);
    assert!(
        bob.has_open_session(&alice_addr),
        "a current restore, even when checkpointed, keeps its sessions"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A test [`SecureStore`]: a fixed in-memory key. A real deployment holds this
/// key in platform secure storage (Keychain / Android Keystore), where the
/// file-rewriter a file-rewriting attacker exploits cannot reach it (decision 0078, anchor B). A
/// test supplies its own so the sealed paths can be exercised without a real
/// Keychain — which is also how these paths are tested in CI, since no Keychain
/// exists there. The same store (same key) must be used for export and restore.
struct FixedKeyStore {
    key: [u8; 32],
    counter: std::sync::atomic::AtomicU64,
}

impl FixedKeyStore {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl SecureStore for FixedKeyStore {
    fn wrap_key(&self) -> Result<[u8; 32], SecureStoreError> {
        Ok(self.key)
    }
    fn rollback_counter(&self) -> Result<u64, SecureStoreError> {
        Ok(self.counter.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn bump_rollback_counter(&self) -> Result<u64, SecureStoreError> {
        Ok(self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1)
    }
}

/// **Anchor B closes the forged-generation gap (decision 0078).** This is the sealed-path counterpart
/// of the `#[ignore]`d `a_forged_generation_defeats_rollback_detection`: the same
/// attack — a file-rewriter forging the generation to `u64::MAX` on an old
/// state — but against `export_state_sealed`/`connect_with_state_sealed`. The
/// generation now lives *inside* an authenticator keyed by secure storage, so
/// forging it breaks the seal, the restore is **refused**, and the rolled-back
/// session never comes back. Not `#[ignore]`d: it asserts the fix.
#[tokio::test]
async fn a_forged_sealed_generation_is_refused() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;
    let store: Arc<dyn SecureStore + Send + Sync> = Arc::new(FixedKeyStore::new([0x5a; 32]));

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    // Rollback protection on from the start: every send commits the counter.
    bob.attach_secure_store(store.clone()).unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut carol = DefaultClient::connect(&client_config(&running, "+carol"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);
    let carol_addr = DeviceAddr::new("+carol", 1);

    // Bob at generation 1, seals a state carrying the Alice session.
    bob.send(&alice_addr, b"hi").await.unwrap();
    alice.receive().await.unwrap();
    let mut blob = bob.export_state_sealed().await.unwrap();

    // Bob advances to 2 and checkpoints, so the directory anchor is 2.
    bob.send(&carol_addr, b"hi").await.unwrap();
    carol.receive().await.unwrap();
    bob.checkpoint().await.unwrap();
    drop(bob);

    // ATTACK: forge the generation to u64::MAX. In the sealed blob the
    // generation is the 8 bytes right after the tag and seal-version bytes
    // (STATE_TAGGED, STATE_VERSION_5, SEAL_VERSION), i.e. indices 3..11. Any
    // change under the authenticator is caught, so the exact offset only makes
    // the test mirror the forged-generation attack precisely.
    blob[3..11].copy_from_slice(&u64::MAX.to_be_bytes());

    // The forged state is REFUSED — unlike the unsealed path, which resumed it.
    let restored = DefaultClient::connect_with_state_sealed(
        &client_config(&running, "+bob"),
        &blob,
        store.clone(),
    )
    .await;
    assert!(
        restored.is_err(),
        "a forged sealed generation must fail the seal and be refused, not resumed"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// The sealed path also catches a *genuine* older state — a legitimate backup
/// restore, or an attacker replaying an untouched old sealed file — via the
/// directory witness, and discards its sessions (decision 3). Unlike the
/// unsealed path, the sealed restore checkpoints on its own (the generation it
/// presents is authenticated, so the witness is a real control), so no explicit
/// `checkpoint` call is needed.
#[tokio::test]
async fn a_rolled_back_sealed_state_is_caught_on_restore() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;
    let store: Arc<dyn SecureStore + Send + Sync> = Arc::new(FixedKeyStore::new([0x5a; 32]));

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    // Rollback protection on from the start: every send commits the counter.
    bob.attach_secure_store(store.clone()).unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut carol = DefaultClient::connect(&client_config(&running, "+carol"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);
    let carol_addr = DeviceAddr::new("+carol", 1);

    bob.send(&alice_addr, b"hi alice").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"hi alice");
    let blob_old = bob.export_state_sealed().await.unwrap();

    // Bob advances to generation 2 and checkpoints; the anchor moves to 2.
    bob.send(&carol_addr, b"hi carol").await.unwrap();
    assert_eq!(carol.receive().await.unwrap()[0].plaintext, b"hi carol");
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::Fresh);
    drop(bob);

    // Restore the genuine old sealed blob: the seal verifies (it is untouched),
    // the sealed path checkpoints, generation 1 < anchor 2 is a rollback, and
    // the sessions are discarded during the restore itself.
    let mut bob = DefaultClient::connect_with_state_sealed(
        &client_config(&running, "+bob"),
        &blob_old,
        store.clone(),
    )
    .await
    .unwrap();
    assert!(
        !bob.has_open_session(&alice_addr),
        "a rolled-back sealed state discards its sessions on restore"
    );
    assert_eq!(
        bob.restore_outcome(),
        RestoreOutcome::SessionsDiscarded,
        "and says so, for the app to show"
    );

    // The identity survives: Bob re-establishes with Alice and talks normally.
    bob.send(&alice_addr, b"fresh session").await.unwrap();
    assert_eq!(
        alice.receive().await.unwrap()[0].plaintext,
        b"fresh session"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Contrast: a *current* sealed state restores Fresh and keeps its sessions, so
/// the sealed path does not disturb the ordinary restart it must not break.
#[tokio::test]
async fn a_current_sealed_state_restores_fresh_and_keeps_its_sessions() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;
    let store: Arc<dyn SecureStore + Send + Sync> = Arc::new(FixedKeyStore::new([0x5a; 32]));

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    // Rollback protection on from the start: every send commits the counter.
    bob.attach_secure_store(store.clone()).unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);

    bob.send(&alice_addr, b"hi").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"hi");
    assert_eq!(bob.checkpoint().await.unwrap(), DirResponse::Fresh);

    let blob = bob.export_state_sealed().await.unwrap();
    drop(bob);

    // The sealed restore checkpoints internally; a current generation is Fresh,
    // so the session stays.
    let bob = DefaultClient::connect_with_state_sealed(
        &client_config(&running, "+bob"),
        &blob,
        store.clone(),
    )
    .await
    .unwrap();
    assert!(
        bob.has_open_session(&alice_addr),
        "a current sealed restore keeps its sessions"
    );
    assert_eq!(bob.restore_outcome(), RestoreOutcome::Resumed);
    assert_eq!(
        alice.restore_outcome(),
        RestoreOutcome::Fresh,
        "a client that restored nothing says so"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// **The secure-storage counter closes same-generation rollback of an older
/// sealed state.** The generation is coarse — it does not
/// move on in-session traffic, so the directory witness alone cannot tell two
/// same-generation saves apart. The `SecureStore` rollback counter can: every
/// send commits it, and each `export_state_sealed` binds the current value, so an
/// older seal carries a lower counter than later sends pushed the store to and is
/// caught on restore.
///
/// Two seals at the same generation; restoring the *older* one discards its
/// sessions (decision 3) while the identity survives.
#[tokio::test]
async fn a_same_generation_older_seal_is_caught_by_the_counter() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;
    let store: Arc<dyn SecureStore + Send + Sync> = Arc::new(FixedKeyStore::new([0x5a; 32]));

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    // Rollback protection on from the start: every send commits the counter.
    bob.attach_secure_store(store.clone()).unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);

    // Establish the session at generation 1 and seal (rollback counter -> 1).
    bob.send(&alice_addr, b"one").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"one");
    let blob_old = bob.export_state_sealed().await.unwrap();

    // More traffic in the SAME session — generation stays 1 — then seal again
    // (rollback counter -> 2). Two sealed states, same generation, different
    // counters.
    bob.send(&alice_addr, b"two").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"two");
    let _blob_new = bob.export_state_sealed().await.unwrap();
    drop(bob);

    // ATTACK: restore the OLDER seal. Its counter (1) is below the store's
    // high-water mark (2), so the restore is caught as a rollback and its
    // sessions are discarded — even though the generation is unchanged and the
    // seal itself is genuine.
    let mut bob = DefaultClient::connect_with_state_sealed(
        &client_config(&running, "+bob"),
        &blob_old,
        store.clone(),
    )
    .await
    .unwrap();
    assert!(
        !bob.has_open_session(&alice_addr),
        "the older same-generation seal is caught by the counter and its session discarded"
    );

    // Identity survives: Bob re-establishes with Alice and talks normally.
    bob.send(&alice_addr, b"fresh session").await.unwrap();
    assert_eq!(
        alice.receive().await.unwrap()[0].plaintext,
        b"fresh session"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// **The per-send counter closes the per-send window.** Without it, restoring
/// the *latest* seal after sends that were never re-sealed would rewind the
/// ratchet, because a counter that advances only at export cannot tell the
/// two apart. Every send commits the counter to secure storage, so a send
/// after the latest seal moves the store's high-water mark past the blob — and
/// the restore is caught as a rollback and its sessions discarded.
#[tokio::test]
async fn a_send_after_the_latest_seal_is_caught_by_the_per_send_counter() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;
    let store: Arc<dyn SecureStore + Send + Sync> = Arc::new(FixedKeyStore::new([0x5a; 32]));

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    // Rollback protection on from the start: every send commits the counter.
    bob.attach_secure_store(store.clone()).unwrap();
    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);

    bob.send(&alice_addr, b"one").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"one");
    // The one and only (latest) seal, at counter 1.
    let blob = bob.export_state_sealed().await.unwrap();

    // A send that is never re-sealed: the ratchet advances past the seal.
    bob.send(&alice_addr, b"two").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"two");
    drop(bob);

    // Restore the latest seal. The send of "two" bumped the store's counter to 2,
    // above the blob's 1, so the restore is a rollback: sessions discarded.
    let bob = DefaultClient::connect_with_state_sealed(
        &client_config(&running, "+bob"),
        &blob,
        store.clone(),
    )
    .await
    .unwrap();
    assert!(
        !bob.has_open_session(&alice_addr),
        "a send after the latest seal is caught by the per-send counter"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Contrast: identity-only persistence (`connect_with_identity`) cannot
/// decrypt a message sent to the *old* session — the new store has no
/// session for it — proving the full-state path is what makes resumption
/// work, not merely keeping the identity.
#[tokio::test]
async fn identity_only_restart_cannot_decrypt_the_old_session() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    alice.send(&bob_addr, b"one").await.unwrap();
    assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"one");

    let bob_identity = bob.export_identity();
    drop(bob);

    // Alice sends to the established session while Bob is down.
    alice.send(&bob_addr, b"orphaned").await.unwrap();

    // Bob restarts with identity only: the message to the old session is
    // undecryptable, so it is dropped (poison-tolerant), and receive keeps
    // waiting — bounded here by a timeout to prove nothing arrived.
    let mut bob =
        DefaultClient::connect_with_identity(&client_config(&running, "+bob"), &bob_identity)
            .await
            .unwrap();
    let timed = tokio::time::timeout(std::time::Duration::from_millis(300), bob.receive()).await;
    assert!(
        timed.is_err(),
        "identity-only restart should not decrypt the orphaned message"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A saved state whose sessions carry a provider tag this client does not
/// run under is restored as identity only: the sessions are dropped rather
/// than carried.
///
/// A session is bound to the provider that established it, so such a session
/// cannot be continued, and a client that tried would decrypt garbage. This is
/// the behaviour the drained-session path relies on — a drained session
/// re-establishes on the next send.
#[tokio::test]
async fn a_state_with_an_unrecognised_provider_tag_does_not_carry_its_sessions() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    alice.send(&bob_addr, b"one").await.unwrap();
    assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"one");

    let mut bob_state = bob.export_state().await.unwrap();
    drop(bob);

    // Re-tag the blob with a tag this client does not run under. The
    // identity and the session bytes are untouched.
    assert_eq!(bob_state[2], SessionProvider::OpenTacenta.to_byte());
    bob_state[2] = SessionProvider::Untagged.to_byte();

    alice.send(&bob_addr, b"orphaned").await.unwrap();

    // The identity still restores, so Bob is the same device to the directory
    // and the relay. The session does not, so the queued message is
    // undecryptable and dropped exactly as the identity-only path drops it.
    let mut bob = DefaultClient::connect_with_state(&client_config(&running, "+bob"), &bob_state)
        .await
        .unwrap();
    let timed = tokio::time::timeout(std::time::Duration::from_millis(300), bob.receive()).await;
    assert!(
        timed.is_err(),
        "a session under an unrecognised provider tag should not be carried across"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A message that can never decrypt is dropped and acknowledged past —
/// the queue advances, and later messages still arrive. Without this, one
/// poison frame would wedge the device's mailbox forever.
#[tokio::test]
async fn a_poison_message_does_not_wedge_the_queue() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    // A session so Bob can decrypt Alice's real messages.
    alice.send(&bob_addr, b"hello").await.unwrap();
    assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"hello");

    // Mallory registers a device and sends Bob bytes that are not a
    // ciphertext at all — undecryptable forever.
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let mallory_addr = DeviceAddr::new("+mallory", 1);
    let bundle = CryptoProvider::publish_bundle(&mut mallory, &mut rng)
        .await
        .unwrap();
    let mut dir = DirConnection::connect(running.directory).await.unwrap();
    let outcome = dir
        .register(
            &mallory_addr,
            CryptoProvider::identity_key(&mallory),
            bundle.clone(),
            |ch| mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Registered);
    let mut mallory_conn = Connection::connect_as(running.relay, &mallory_addr, |ch| {
        mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    let poison = encode_request(&Request::Send {
        to: bob_addr.clone(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: vec![0xFF, 0xFF, 0xFF, 0xFF],
        },
    });
    assert!(matches!(
        decode_response(&mallory_conn.request(&poison).await.unwrap()),
        Some(Response::Ok)
    ));

    // A real message behind the poison one.
    alice.send(&bob_addr, b"after poison").await.unwrap();

    // Bob gets the real message; the poison one is dropped and acked past.
    let got = bob.receive().await.unwrap();
    let texts: Vec<&[u8]> = got.iter().map(|m| m.plaintext.as_slice()).collect();
    assert_eq!(texts, vec![b"after poison".as_slice()]);

    // The queue is not wedged: conversation continues normally.
    alice.send(&bob_addr, b"still flowing").await.unwrap();
    assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"still flowing");

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// **A sealed state is bound to its address.** Offered to another
/// user or device, it is refused before that identity is registered under
/// the wrong address, where trust-on-first-use would have kept it.
#[tokio::test]
async fn a_sealed_state_for_another_address_is_refused() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;
    let store: Arc<dyn SecureStore + Send + Sync> = Arc::new(FixedKeyStore::new([0x5a; 32]));

    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    bob.attach_secure_store(store.clone()).unwrap();
    let blob = bob.export_state_sealed().await.unwrap();
    drop(bob);

    let as_carol =
        DefaultClient::connect_with_state_sealed(&client_config(&running, "+carol"), &blob, store)
            .await;
    match as_carol {
        Err(e) => {
            assert!(matches!(e, Error::StateMismatch { .. }), "{e}");
            assert_eq!(e.kind(), ErrorKind::IdentityMismatch);
        }
        Ok(_) => panic!("bob's sealed state must not restore as carol"),
    }
    // Carol's address stays unbound: a fresh connect as her works.
    DefaultClient::connect(&client_config(&running, "+carol"))
        .await
        .expect("carol was never bound to bob's identity");

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// **One store per client, and a monotone one.** A second attach
/// is refused, and a store whose counter stops advancing (reset or
/// replaced under the client) fails the send it could not protect.
#[tokio::test]
async fn the_store_is_attached_once_and_must_advance() {
    let data_dir = scratch_dir();
    let config = server_config(&data_dir);
    let running = Running::start(&config).await;

    let mut alice = DefaultClient::connect(&client_config(&running, "+alice"))
        .await
        .unwrap();
    let mut bob = DefaultClient::connect(&client_config(&running, "+bob"))
        .await
        .unwrap();
    let alice_addr = DeviceAddr::new("+alice", 1);
    let stuck = Arc::new(StuckStore::default());
    bob.attach_secure_store(stuck.clone()).unwrap();
    let again = bob.attach_secure_store(Arc::new(FixedKeyStore::new([0x11; 32])));
    assert!(
        matches!(again, Err(Error::InvalidArgument(_))),
        "a second store is refused: {again:?}"
    );

    // The first bump advances (1 after 0) and the send goes through.
    bob.send(&alice_addr, b"one").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"one");
    // The store stops advancing: the next send is refused as State.
    stuck.freeze();
    let refused = bob.send(&alice_addr, b"two").await.unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::State, "{refused}");

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A store that can be told to stop advancing its counter.
#[derive(Default)]
struct StuckStore {
    counter: std::sync::atomic::AtomicU64,
    frozen: std::sync::atomic::AtomicBool,
}

impl StuckStore {
    fn freeze(&self) {
        self.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SecureStore for StuckStore {
    fn wrap_key(&self) -> Result<[u8; 32], SecureStoreError> {
        Ok([0x22; 32])
    }
    fn rollback_counter(&self) -> Result<u64, SecureStoreError> {
        Ok(self.counter.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn bump_rollback_counter(&self) -> Result<u64, SecureStoreError> {
        if self.frozen.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(self.counter.load(std::sync::atomic::Ordering::SeqCst));
        }
        Ok(self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1)
    }
}
