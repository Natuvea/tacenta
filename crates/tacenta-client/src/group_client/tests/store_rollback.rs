//! A store that goes back to an older snapshot under a running coordinator (decisions 0143, 0147):
//! the fence freezes the coordinator, and `recover` refuses to adopt the older state, which would
//! send at ratchet positions the peers have already seen. Every test drives `GroupClient` against
//! the in-process directory and relay with the real provider.

use super::*;

/// Alice's direct messages to a peer that reads them, and what the peer has been shown.
async fn shown_to(peer: &mut GroupClient) -> (Vec<String>, usize) {
    let mut shown = Vec::new();
    let mut dropped = 0;
    for _ in 0..3 {
        let inbound = peer.receive(0).await.unwrap();
        dropped += inbound.dropped;
        shown.extend(
            inbound
                .direct
                .iter()
                .map(|message| String::from_utf8_lossy(&message.plaintext).to_string()),
        );
    }
    (shown, dropped)
}

/// Three sends, a backup taken after the first, the backup put back under the running coordinator:
/// the next send is refused as frozen (0143), `recover` refuses the older snapshot and stays frozen
/// however often it is called (0147), and nothing goes out at a position the peer has used.
#[tokio::test]
async fn a_store_put_back_to_an_older_snapshot_is_not_adopted_by_recover() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    let peer_store = SharedStore::default();
    let mut peer = coordinator(directory, relay, "+peer", &peer_store).await;
    let peer_route = route(&peer);
    alice.send_direct(&peer_route, b"one").await.unwrap();
    let backup = store.durable().unwrap();
    alice.send_direct(&peer_route, b"two").await.unwrap();
    alice.send_direct(&peer_route, b"three").await.unwrap();
    let newest = alice.generation();
    assert!(backup.generation() < newest);
    store.0.lock().unwrap().snapshot = Some(backup.clone());

    let refused = alice.send_direct(&peer_route, b"four").await;
    assert!(matches!(refused, Err(GroupError::Frozen)), "{refused:?}");
    for _ in 0..2 {
        let recovered = alice.recover().await;
        assert!(
            matches!(recovered, Err(GroupError::Rollback)),
            "{recovered:?}"
        );
        assert!(alice.is_frozen());
        assert_eq!(
            alice.generation(),
            newest,
            "the coordinator kept its own state"
        );
    }
    let still = alice.send_direct(&peer_route, b"five").await;
    assert!(matches!(still, Err(GroupError::Frozen)), "{still:?}");
    assert_eq!(
        store.durable().unwrap(),
        backup,
        "nothing was written to the store"
    );

    let (shown, dropped) = shown_to(&mut peer).await;
    assert_eq!(shown, ["one", "two", "three"]);
    assert_eq!(dropped, 0);

    // The way on is the caller's decision: a new coordinator over the state it vouches for. The
    // peer has seen the positions this state reuses, and drops what is sent at them.
    drop(alice);
    let config = config(directory, relay, "+alice", 1);
    let mut reopened = restart(&config, &store).await;
    assert!(!reopened.is_frozen());
    assert_eq!(reopened.generation(), backup.generation());
    reopened.send_direct(&peer_route, b"six").await.unwrap();
    let (shown, dropped) = shown_to(&mut peer).await;
    assert!(shown.is_empty(), "{shown:?}");
    assert_eq!(dropped, 1);
}

/// The same with the native file store and the backup put back over its file, which is how an
/// operator or a sync tool does it.
#[tokio::test]
async fn a_backup_put_back_over_a_running_file_store_is_not_adopted_by_recover() {
    let (directory, relay) = start_server().await;
    let dir = std::env::temp_dir().join(format!("tacenta-rollback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.bin");
    let mut alice = GroupClient::open(
        plain(directory, relay, "+alice").await,
        FileOperationStore::new(&path),
    )
    .await
    .unwrap();
    let peer_store = SharedStore::default();
    let mut peer = coordinator(directory, relay, "+peer", &peer_store).await;
    let peer_route = route(&peer);
    alice.send_direct(&peer_route, b"one").await.unwrap();
    let backup = std::fs::read(&path).unwrap();
    alice.send_direct(&peer_route, b"two").await.unwrap();
    alice.send_direct(&peer_route, b"three").await.unwrap();
    std::fs::write(&path, &backup).unwrap();

    let refused = alice.send_direct(&peer_route, b"four").await;
    assert!(matches!(refused, Err(GroupError::Frozen)), "{refused:?}");
    let recovered = alice.recover().await;
    assert!(
        matches!(recovered, Err(GroupError::Rollback)),
        "{recovered:?}"
    );
    assert!(alice.is_frozen());
    let still = alice.send_direct(&peer_route, b"five").await;
    assert!(matches!(still, Err(GroupError::Frozen)), "{still:?}");
    assert_eq!(std::fs::read(&path).unwrap(), backup);
    let (shown, dropped) = shown_to(&mut peer).await;
    assert_eq!(shown, ["one", "two", "three"]);
    assert_eq!(dropped, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A write that failed, or whose outcome was unknown and did not land, leaves the store at the
/// generation before it. That is the case `recover` exists for, and it is not a rollback: only a
/// snapshot the coordinator saw committed raises the mark.
#[tokio::test]
async fn a_write_that_did_not_land_is_recovered_not_refused_as_a_rollback() {
    for bad in [CommitOutcome::Failed, CommitOutcome::Unknown] {
        let (directory, relay) = start_server().await;
        let store = SharedStore::default();
        let mut alice = coordinator(directory, relay, "+alice", &store).await;
        let peer_store = SharedStore::default();
        let peer = coordinator(directory, relay, "+peer", &peer_store).await;
        let peer_route = route(&peer);
        alice.send_direct(&peer_route, b"one").await.unwrap();
        store.script([bad], false);
        let failed = alice.send_direct(&peer_route, b"two").await;
        assert!(matches!(failed, Err(GroupError::Frozen)), "{bad:?}");
        alice.recover().await.unwrap();
        assert!(!alice.is_frozen(), "{bad:?}");
        alice.send_direct(&peer_route, b"three").await.unwrap();
    }
}

/// Another writer that published a newer snapshot is what `recover` adopts (0143): a newer
/// generation is never a rollback.
#[tokio::test]
async fn a_newer_snapshot_from_another_writer_is_adopted_by_recover() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    let peer_store = SharedStore::default();
    let peer = coordinator(directory, relay, "+peer", &peer_store).await;
    let peer_route = route(&peer);
    alice.send_direct(&peer_route, b"one").await.unwrap();
    let mut newer = store.durable().unwrap();
    newer.generation += 5;
    store.0.lock().unwrap().snapshot = Some(newer.clone());
    let refused = alice.send_direct(&peer_route, b"two").await;
    assert!(matches!(refused, Err(GroupError::Frozen)), "{refused:?}");
    alice.recover().await.unwrap();
    assert!(!alice.is_frozen());
    assert_eq!(alice.generation(), newer.generation);
}
