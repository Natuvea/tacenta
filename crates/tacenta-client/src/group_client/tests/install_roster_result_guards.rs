//! What `GroupClient::install_roster` reports for each recipient (decisions 0124 and 0141,
//! `crates/tacenta-client/src/group_client.rs`): `delivered`, `pending` (the control is committed and
//! the relay has not taken it) and `unprepared` (no control could be prepared), and the refusal of an
//! older roster whose controls were once sent.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay; the tests of
//! failed sends put a proxy in front of the sender's relay connection that drops every `Send`
//! request while it is armed.
//!
//! - R088: the shortcut for a control that was already sent applies before the successor is installed.
//! - R091, R093: a recipient whose control is exhausted, or whose send the relay did not take, is
//!   reported `unprepared` instead of `pending`.
//! - R094: a recipient that could not be prepared after the install is reported `pending` instead of
//!   `unprepared`.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Forwards length-prefixed frames to `relay`. While `cut` is set, a `Send` request is not forwarded
/// and the connection is closed, so the client sees a network error for that request.
async fn send_fault_proxy(relay: SocketAddr, cut: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let Ok(server) = TcpStream::connect(relay).await else {
                return;
            };
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n) = server_read.read(&mut buf).await {
                    if n == 0 || client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = client_write.shutdown().await;
            });
            let cut = cut.clone();
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 4];
                    if client_read.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                    if client_read.read_exact(&mut body).await.is_err() {
                        break;
                    }
                    let is_send = matches!(
                        tacenta_relay::decode_request(&body),
                        Some(tacenta_relay::Request::Send { .. })
                    );
                    if is_send && cut.load(Ordering::SeqCst) {
                        break;
                    }
                    if server_write.write_all(&len).await.is_err()
                        || server_write.write_all(&body).await.is_err()
                        || server_write.flush().await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Alice (authority) with an empty group, connected to the relay through the fault proxy, and Bob
/// (a coordinator that has joined the group at genesis) connected directly.
struct Behind {
    alice: GroupClient,
    bob: GroupClient,
    cut: Arc<AtomicBool>,
    alice_member: Member,
    bob_member: Member,
    bob_route: DeviceAddr,
}

async fn behind_the_proxy() -> Behind {
    let (directory, relay) = start_server().await;
    let cut = Arc::new(AtomicBool::new(false));
    let proxy = send_fault_proxy(relay, cut.clone()).await;
    let alice_store = SharedStore::default();
    let alice_client = DefaultClient::connect(&config(directory, proxy, "+alice", 1))
        .await
        .unwrap();
    let mut alice = GroupClient::open(alice_client, alice_store).await.unwrap();
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    Behind {
        alice,
        bob,
        cut,
        alice_member,
        bob_member,
        bob_route,
    }
}

/// R093: in `install_roster`, `Err(_) => pending.push(recipient.clone())` after the dispatch of a
/// prepared control becomes `unprepared.push(..)`, so a control that is committed and that the relay
/// did not take is reported as one that was never prepared.
#[tokio::test]
async fn r093_a_control_the_relay_did_not_take_is_pending_not_unprepared() {
    let mut b = behind_the_proxy().await;
    let r1 = b
        .alice
        .next_roster(vec![b.alice_member.clone(), b.bob_member.clone()])
        .unwrap();
    b.cut.store(true, Ordering::SeqCst);
    let install = b
        .alice
        .install_roster(r1, &[(b.bob_member.clone(), b.bob_route.clone())], None, 0)
        .await
        .unwrap();
    assert_eq!(install.pending, [b.bob_member.clone()], "{install:?}");
    assert!(install.unprepared.is_empty() && install.delivered.is_empty());
    assert_eq!(b.alice.roster().unwrap().revision, 1, "it is installed");
    assert!(b.bob.receive(0).await.unwrap().items.is_empty());
}

/// R091: in `install_roster`, the arm for a control that reached a final state without being accepted
/// (exhausted, cancelled) reports the recipient `unprepared` instead of `pending`. The third send of
/// a control is its last; a fourth call finds it exhausted.
#[tokio::test]
async fn r091_a_control_whose_attempts_are_used_up_is_pending_not_unprepared() {
    let mut b = behind_the_proxy().await;
    let r1 = b
        .alice
        .next_roster(vec![b.alice_member.clone(), b.bob_member.clone()])
        .unwrap();
    let recipients = [(b.bob_member.clone(), b.bob_route.clone())];
    b.cut.store(true, Ordering::SeqCst);
    for attempt in 1..=3 {
        let install = b
            .alice
            .install_roster(r1.clone(), &recipients, None, 0)
            .await
            .unwrap();
        assert_eq!(
            install.pending,
            [b.bob_member.clone()],
            "{attempt}: {install:?}"
        );
    }
    let exhausted = b
        .alice
        .install_roster(r1, &recipients, None, 0)
        .await
        .unwrap();
    assert_eq!(exhausted.pending, [b.bob_member.clone()], "{exhausted:?}");
    assert!(exhausted.unprepared.is_empty() && exhausted.delivered.is_empty());
}

/// Alice (authority) with Bob and Carol in the group at revision 1.
async fn three_members() -> (GroupClient, [(Member, DeviceAddr); 2]) {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (bob, _bs) = joined(directory, relay, "+bob", &alice_member).await;
    let (carol, _cs) = joined(directory, relay, "+carol", &alice_member).await;
    let bob_entry = (bob.member().unwrap(), route(&bob));
    let carol_entry = (carol.member().unwrap(), route(&carol));
    let r1 = alice
        .next_roster(vec![
            alice_member,
            bob_entry.0.clone(),
            carol_entry.0.clone(),
        ])
        .unwrap();
    alice
        .install_roster(r1, &[bob_entry.clone(), carol_entry.clone()], None, 0)
        .await
        .unwrap();
    (alice, [bob_entry, carol_entry])
}

/// R094: in `install_roster`, `unprepared.push(recipient.clone())` for a recipient that cannot be
/// prepared once the successor is installed becomes `pending.push(..)`. Here the roster record of
/// the replaced roster is gone from the retained control records, so the member the install removes
/// can no longer be told, and that is not a control waiting for the relay.
#[tokio::test]
async fn r094_a_removed_member_that_can_no_longer_be_told_is_unprepared_not_pending() {
    let (mut alice, [(bob, bob_route), (carol, carol_route)]) = three_members().await;
    alice
        .snapshot
        .group_controls
        .retain(|record| !record.starts_with(b"TCGC"));
    let r2 = alice
        .next_roster(vec![alice.member().unwrap(), carol.clone()])
        .unwrap();
    let install = alice
        .install_roster(
            r2,
            &[(carol.clone(), carol_route), (bob.clone(), bob_route)],
            None,
            0,
        )
        .await
        .unwrap();
    assert_eq!(install.delivered, [carol], "{install:?}");
    assert_eq!(install.unprepared, [bob], "{install:?}");
    assert!(install.pending.is_empty());
}

/// R088: in `install_roster`, `if installed && let Ok(existing) = ..` loses `installed &&`, so the
/// shortcut for a control that was already sent applies to an older roster too, and an older roster
/// is answered as delivered instead of being refused as stale.
#[tokio::test]
async fn r088_an_older_roster_is_refused_not_answered_from_the_controls_once_sent() {
    let (mut alice, [(bob, bob_route), (_carol, _carol_route)]) = three_members().await;
    let r1 = alice.roster().unwrap().clone();
    let r2 = alice.next_roster(vec![alice.member().unwrap()]).unwrap();
    alice
        .install_roster(r2, &[(bob.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    assert_eq!(alice.roster().unwrap().revision, 2);
    let before = alice.generation();
    let again = alice.install_roster(r1, &[(bob, bob_route)], None, 0).await;
    assert!(matches!(again, Err(GroupError::Policy)), "{again:?}");
    assert_eq!(alice.roster().unwrap().revision, 2);
    assert_eq!(alice.generation(), before, "nothing was committed");
}
