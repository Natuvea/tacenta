//! Event redelivery and receive faults (decisions 0131, 0144): a failed
//! acknowledgement after the commit, the three-item crash matrix, the delivery
//! cursor and the scrub of delivered plaintext, the per-call bound, events that
//! were evicted, and randomised fault schedules on the receiving side. Every test
//! drives `GroupClient` against the in-process directory and relay with the real
//! provider; the acknowledgement faults come from a relay proxy that cuts the
//! connection at the first `Ack`. `GROUP_FAULT_SEEDS`, `GROUP_FAULT_OPS` and
//! `GROUP_FAULT_BASE` tune the randomised schedule (defaults 40, 30 and 1).

use super::durable_root::Xorshift;
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// A relay proxy that cuts the connection at the first acknowledgement.
// ---------------------------------------------------------------------------

const FAULT_NONE: u8 = 0;

const FAULT_DROP_BEFORE_ACK: u8 = 1; // the ack never reaches the relay
const FAULT_DROP_AFTER_ACK: u8 = 2; // the relay gets the ack; the client never sees the reply

/// Forwards length-prefixed frames to `relay`. When `fault` is armed, the next
/// `Ack` request is either not forwarded or forwarded without its reply, and the
/// connection is closed. One-shot: the fault disarms itself.
async fn ack_fault_proxy(relay: SocketAddr, fault: Arc<AtomicU8>) -> SocketAddr {
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
            let cut = Arc::new(AtomicBool::new(false));
            let cut_for_reply = cut.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n) = server_read.read(&mut buf).await {
                    if n == 0 || cut_for_reply.load(Ordering::SeqCst) {
                        break;
                    }
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = client_write.shutdown().await;
            });
            let fault = fault.clone();
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
                    let is_ack = matches!(
                        tacenta_relay::decode_request(&body),
                        Some(tacenta_relay::Request::Ack { .. })
                    );
                    let mode = if is_ack {
                        fault.swap(FAULT_NONE, Ordering::SeqCst)
                    } else {
                        FAULT_NONE
                    };
                    if mode == FAULT_DROP_BEFORE_ACK {
                        cut.store(true, Ordering::SeqCst);
                        break;
                    }
                    if mode == FAULT_DROP_AFTER_ACK {
                        cut.store(true, Ordering::SeqCst);
                    }
                    if server_write.write_all(&len).await.is_err()
                        || server_write.write_all(&body).await.is_err()
                        || server_write.flush().await.is_err()
                    {
                        break;
                    }
                    if mode == FAULT_DROP_AFTER_ACK {
                        // Give the relay time to process the ack, then close.
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Alice (authority, plain coordinator) and Bob (coordinator behind the fault
/// proxy) at revision 1, with one application message from Alice waiting.
struct Pair {
    bob: GroupClient,
    bob_store: SharedStore,
    bob_config: Config,
    alice: GroupClient,
    alice_member: Member,
    bob_member: Member,
    bob_route: DeviceAddr,
    fault: Arc<AtomicU8>,
    directory: SocketAddr,
    relay: SocketAddr,
}

async fn pair_behind_proxy() -> Pair {
    let (directory, relay) = start_server().await;
    let fault = Arc::new(AtomicU8::new(FAULT_NONE));
    let proxy = ack_fault_proxy(relay, fault.clone()).await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let bob_store = SharedStore::default();
    let bob_config = config(directory, proxy, "+bob", 1);
    let mut bob = GroupClient::open(
        DefaultClient::connect(&bob_config).await.unwrap(),
        bob_store.clone(),
    )
    .await
    .unwrap();
    bob.join_group(genesis_of(&alice_member), alice_member.clone())
        .unwrap();
    let bob_member = bob.member().unwrap();
    let bob_route = bob.address().clone();
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted
    );
    Pair {
        bob,
        bob_store,
        bob_config,
        alice,
        alice_member,
        bob_member,
        bob_route,
        fault,
        directory,
        relay,
    }
}

async fn failed_ack_case(mode: u8, ack_reached_the_relay: bool) {
    let mut p = pair_behind_proxy().await;
    p.alice
        .send_group(
            &[(p.bob_member.clone(), p.bob_route.clone())],
            b"the only copy".to_vec(),
        )
        .await
        .unwrap();
    p.fault.store(mode, Ordering::SeqCst);
    let first = p.bob.receive(0).await;
    // The commit succeeded and only the acknowledgement failed: the call reports
    // the error, the event is durable, and the coordinator is not frozen.
    assert!(first.is_err(), "the acknowledgement was cut");
    assert!(!p.bob.is_frozen());
    let durable = p.bob_store.durable().unwrap();
    assert!(
        durable
            .inbox
            .iter()
            .any(|record| record.starts_with(b"TCGR"))
    );
    assert_eq!(durable.delivery_cursor, 0, "nothing was handed over");
    // The next call offers the event it never showed, with its event ID.
    let second = p.bob.receive(0).await.unwrap();
    assert_eq!(second.redelivered.len(), 1);
    assert_eq!(second.redelivered[0].event_id, 0);
    assert_eq!(second.redelivered[0].payload, b"the only copy");
    assert_eq!(second.events().len(), 1);
    assert_eq!(second.lost_events, 0);
    // The relay's copy is refused by the provider (its key is consumed) and
    // dropped, unless the acknowledgement had reached the relay.
    assert_eq!(second.dropped, usize::from(!ack_reached_the_relay));
    // Handed over once, acknowledged by the next call, offered no more.
    let third = p.bob.receive(0).await.unwrap();
    assert!(third.events().is_empty() && third.redelivered.is_empty());
    assert_eq!(third.lost_events, 0);
    assert_eq!(p.bob_store.durable().unwrap().delivery_cursor, 1);
    let _ = (&p.bob_config, &p.alice_member, p.directory, p.relay);
}

#[tokio::test]
async fn a_failed_acknowledgement_redelivers_the_committed_event_when_the_relay_never_got_it() {
    failed_ack_case(FAULT_DROP_BEFORE_ACK, false).await;
}

#[tokio::test]
async fn a_failed_acknowledgement_redelivers_the_committed_event_when_the_relay_did_get_it() {
    failed_ack_case(FAULT_DROP_AFTER_ACK, true).await;
}

// ---------------------------------------------------------------------------
// Crash matrix on a three-item batch: which commit fails, how, and how the
// coordinator comes back.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fail {
    Failed,
    UnknownNotLanded,
    UnknownLanded,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Back {
    InProcess,
    Restart,
}

/// What the application was shown across a failing three-item batch: the
/// `(event ID, payload)` pairs handed over by the call that hit the fault
/// (`before`) and by the calls after the coordinator came back (`after`).
struct Shown {
    before: Vec<(u64, Vec<u8>)>,
    after: Vec<(u64, Vec<u8>)>,
    froze: bool,
    lost_events: u64,
}

async fn batch_case(k: usize, fail: Fail, back: Back) -> Shown {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_config = config(directory, relay, "+bob", 1);
    let bob_member = bob.member().unwrap();
    let bob_route = bob.address().clone();
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    for text in [&b"m0"[..], b"m1", b"m2"] {
        alice
            .send_group(&[(bob_member.clone(), bob_route.clone())], text.to_vec())
            .await
            .unwrap();
    }
    let mut outcomes = vec![CommitOutcome::Committed; k];
    let (bad, lands) = match fail {
        Fail::Failed => (CommitOutcome::Failed, false),
        Fail::UnknownNotLanded => (CommitOutcome::Unknown, false),
        Fail::UnknownLanded => (CommitOutcome::Unknown, true),
    };
    outcomes.push(bad);
    bob_store.script(outcomes, lands);
    let pairs = |inbound: &Inbound| -> Vec<(u64, Vec<u8>)> {
        inbound
            .events()
            .iter()
            .map(|event| (event.event_id, event.payload.clone()))
            .collect()
    };
    let first = bob.receive(0).await.unwrap();
    let froze = first.frozen;
    let before = pairs(&first);
    match back {
        Back::InProcess => bob.recover().await.unwrap(),
        Back::Restart => {
            drop(bob);
            bob = restart(&bob_config, &bob_store).await;
            bob.join_group(genesis_of(&alice_member), alice_member.clone())
                .unwrap();
        }
    }
    let mut after = Vec::new();
    let mut lost_events = 0;
    for _ in 0..4 {
        let inbound = bob.receive(0).await.unwrap();
        lost_events += inbound.lost_events;
        after.extend(pairs(&inbound));
    }
    Shown {
        before,
        after,
        froze,
        lost_events,
    }
}

#[tokio::test]
async fn the_three_item_crash_matrix_shows_every_event_and_loses_none() {
    // The commit of item `k` of a three-item batch fails (`failed`, `unknown`
    // that did not land, `unknown` that landed) and the coordinator comes back in
    // process or from its store. Every event is shown; one shown before a restart
    // may be offered again after it, with the same ID; nothing is lost.
    for back in [Back::InProcess, Back::Restart] {
        for fail in [Fail::Failed, Fail::UnknownNotLanded, Fail::UnknownLanded] {
            for k in 0..3usize {
                let case = format!("back={back:?} fail={fail:?} k={k}");
                let shown = batch_case(k, fail, back).await;
                assert!(shown.froze, "{case}: a failing commit freezes the batch");
                assert_eq!(shown.lost_events, 0, "{case}");
                // The prefix before the failing item was committed and handed over.
                assert_eq!(shown.before.len(), k, "{case}");
                let mut everything = shown.before.clone();
                everything.extend(shown.after.clone());
                for (index, text) in ["m0", "m1", "m2"].iter().enumerate() {
                    let copies: Vec<_> = everything
                        .iter()
                        .filter(|(_, payload)| payload == text.as_bytes())
                        .collect();
                    // Bob was already told of the group at revision 1 with no
                    // events, so the three messages take event IDs 0, 1 and 2.
                    assert!(!copies.is_empty(), "{case}: {text} was lost");
                    assert!(
                        copies.iter().all(|(id, _)| *id == index as u64),
                        "{case}: {text} changed its event ID: {copies:?}"
                    );
                    let repeated = copies.len() > 1;
                    let may_repeat = back == Back::Restart && index < k;
                    assert!(
                        !repeated || may_repeat,
                        "{case}: {text} was shown twice without a restart between: {copies:?}"
                    );
                    assert!(copies.len() <= 2, "{case}: {text}: {copies:?}");
                }
            }
        }
    }
}

#[tokio::test]
async fn delivered_group_plaintext_leaves_the_snapshot_when_the_caller_acknowledges_it() {
    let mut d = duo_with_group_bob().await;
    let marker = b"MARKER-secret-plaintext-0123456789";
    d.0.send_group(&[(d.3.clone(), d.4.clone())], marker.to_vec())
        .await
        .unwrap();
    let inbound = d.1.receive(0).await.unwrap();
    assert_eq!(inbound.events().len(), 1);
    let has = |store: &SharedStore| {
        let bytes = store.durable().unwrap().encode().unwrap();
        bytes.windows(marker.len()).any(|w| w == marker)
    };
    // Until the caller acknowledges it, the event is retained so that it can be
    // offered again; the snapshot is unsealed.
    assert!(has(&d.2));
    assert_eq!(d.1.delivery_cursor(), 0);
    d.1.acknowledge_delivery().unwrap();
    assert_eq!(d.1.delivery_cursor(), 1);
    assert!(
        !has(&d.2),
        "the plaintext of an acknowledged event is not kept"
    );
    // The record stays, without its context: the disposition is still audited.
    let durable = d.2.durable().unwrap();
    assert!(
        durable
            .inbox
            .iter()
            .any(|record| record.starts_with(b"TCGR"))
    );
    assert_eq!(durable.delivery_cursor, 1);
    // Nothing is offered again, and acknowledging twice commits nothing.
    let generation = d.1.generation();
    d.1.acknowledge_delivery().unwrap();
    assert_eq!(d.1.generation(), generation);
    let next = d.1.receive(0).await.unwrap();
    assert!(next.events().is_empty() && next.redelivered.is_empty());
    // The sender's outbox keeps the context of the sends it retains (0133).
    let alice_has = {
        let bytes = d.5.durable().unwrap().encode().unwrap();
        bytes.windows(marker.len()).any(|w| w == marker)
    };
    assert!(alice_has);
}

#[tokio::test]
async fn the_next_receive_acknowledges_what_the_previous_call_handed_over() {
    let mut d = duo_with_group_bob().await;
    let marker = b"MARKER-second-path-0123456789";
    d.0.send_group(&[(d.3.clone(), d.4.clone())], marker.to_vec())
        .await
        .unwrap();
    let first = d.1.receive(0).await.unwrap();
    assert_eq!(first.events().len(), 1);
    assert_eq!(d.1.delivery_cursor(), 0);
    let second = d.1.receive(0).await.unwrap();
    assert!(second.events().is_empty());
    assert_eq!(d.1.delivery_cursor(), 1);
    let bytes = d.2.durable().unwrap().encode().unwrap();
    assert!(!bytes.windows(marker.len()).any(|w| w == marker));
}

#[tokio::test]
async fn a_process_that_stops_before_acknowledging_is_offered_the_events_again_with_the_same_ids() {
    let mut p = pair_behind_proxy().await;
    for text in ["one", "two", "three"] {
        p.alice
            .send_group(
                &[(p.bob_member.clone(), p.bob_route.clone())],
                text.as_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
    let first = p.bob.receive(0).await.unwrap();
    let ids: Vec<_> = first.events().iter().map(|e| e.event_id).collect();
    assert_eq!(ids, [0, 1, 2]);
    // The process ends before the caller acknowledged anything.
    drop(p.bob);
    let mut bob = restart(&p.bob_config, &p.bob_store).await;
    bob.join_group(genesis_of(&p.alice_member), p.alice_member.clone())
        .unwrap();
    let again = bob.receive(0).await.unwrap();
    let offered: Vec<_> = again
        .redelivered
        .iter()
        .map(|e| (e.event_id, e.payload.clone()))
        .collect();
    assert_eq!(
        offered,
        [
            (0, b"one".to_vec()),
            (1, b"two".to_vec()),
            (2, b"three".to_vec())
        ]
    );
    // A caller that stored them says so before it stops, and is not offered them
    // again.
    bob.acknowledge_delivery().unwrap();
    drop(bob);
    let mut bob = restart(&p.bob_config, &p.bob_store).await;
    bob.join_group(genesis_of(&p.alice_member), p.alice_member.clone())
        .unwrap();
    let quiet = bob.receive(0).await.unwrap();
    assert!(quiet.events().is_empty() && quiet.redelivered.is_empty());
    assert_eq!(quiet.lost_events, 0);
    assert_eq!(bob.delivery_cursor(), 3);
}

#[tokio::test]
async fn redelivered_events_come_first_in_id_order_and_new_ones_follow() {
    let mut p = pair_behind_proxy().await;
    let to_bob = [(p.bob_member.clone(), p.bob_route.clone())];
    for text in ["e0", "e1"] {
        p.alice
            .send_group(&to_bob, text.as_bytes().to_vec())
            .await
            .unwrap();
    }
    p.fault.store(FAULT_DROP_BEFORE_ACK, Ordering::SeqCst);
    assert!(p.bob.receive(0).await.is_err());
    p.alice.send_group(&to_bob, b"e2".to_vec()).await.unwrap();
    let inbound = p.bob.receive(0).await.unwrap();
    let ids: Vec<_> = inbound
        .events()
        .iter()
        .map(|event| (event.event_id, event.payload.clone()))
        .collect();
    assert_eq!(
        ids,
        [
            (0, b"e0".to_vec()),
            (1, b"e1".to_vec()),
            (2, b"e2".to_vec())
        ]
    );
    assert_eq!(
        inbound.redelivered.len(),
        2,
        "two were redelivered, one is new"
    );
}

#[tokio::test]
async fn an_acknowledgement_that_cannot_commit_freezes_and_is_retried_after_recovery() {
    let mut p = pair_behind_proxy().await;
    let to_bob = [(p.bob_member.clone(), p.bob_route.clone())];
    p.alice
        .send_group(&to_bob, b"first".to_vec())
        .await
        .unwrap();
    assert_eq!(p.bob.receive(0).await.unwrap().events().len(), 1);
    p.bob_store.script([CommitOutcome::Failed], false);
    assert!(matches!(
        p.bob.acknowledge_delivery(),
        Err(GroupError::Frozen)
    ));
    assert!(p.bob.is_frozen());
    assert_eq!(p.bob_store.durable().unwrap().delivery_cursor, 0);
    // In the same process the caller did get the event, so recovery does not
    // offer it again: the next call commits the acknowledgement that failed.
    p.bob.recover().await.unwrap();
    let next = p.bob.receive(0).await.unwrap();
    assert!(next.events().is_empty() && next.redelivered.is_empty());
    assert_eq!(p.bob.delivery_cursor(), 1);
    assert_eq!(p.bob_store.durable().unwrap().delivery_cursor, 1);

    // A process that stops after the acknowledgement failed to commit is offered
    // the event again by its successor.
    p.alice
        .send_group(&to_bob, b"second".to_vec())
        .await
        .unwrap();
    assert_eq!(p.bob.receive(0).await.unwrap().events().len(), 1);
    p.bob_store.script([CommitOutcome::Unknown], false);
    assert!(matches!(
        p.bob.acknowledge_delivery(),
        Err(GroupError::Frozen)
    ));
    drop(p.bob);
    let mut bob = restart(&p.bob_config, &p.bob_store).await;
    bob.join_group(genesis_of(&p.alice_member), p.alice_member.clone())
        .unwrap();
    let again = bob.receive(0).await.unwrap();
    assert_eq!(again.redelivered.len(), 1);
    assert_eq!(again.redelivered[0].event_id, 1);
    assert_eq!(again.redelivered[0].payload, b"second");
}

#[tokio::test]
async fn events_evicted_before_they_were_delivered_are_counted_not_hidden() {
    let mut p = pair_behind_proxy().await;
    let to_bob = [(p.bob_member.clone(), p.bob_route.clone())];
    for text in ["a", "b", "c", "d", "e"] {
        p.alice
            .send_group(&to_bob, text.as_bytes().to_vec())
            .await
            .unwrap();
    }
    p.fault.store(FAULT_DROP_BEFORE_ACK, Ordering::SeqCst);
    assert!(p.bob.receive(0).await.is_err());
    // Retention is the newest 64 `inbox` records (0133): drop the two oldest as
    // later traffic would have.
    p.bob.snapshot.inbox.drain(..2);
    let inbound = p.bob.receive(0).await.unwrap();
    let ids: Vec<_> = inbound.redelivered.iter().map(|e| e.event_id).collect();
    assert_eq!(ids, [2, 3, 4]);
    assert_eq!(
        inbound.lost_events, 2,
        "events 0 and 1 cannot be redelivered"
    );
}

#[tokio::test]
async fn one_receive_call_processes_at_most_thirty_two_relay_items() {
    let mut p = pair_behind_proxy().await;
    let to_bob = [(p.bob_member.clone(), p.bob_route.clone())];
    for index in 0..40u8 {
        p.alice.send_group(&to_bob, vec![index]).await.unwrap();
    }
    let first = p.bob.receive(0).await.unwrap();
    assert_eq!(first.items.len(), 32);
    let second = p.bob.receive(0).await.unwrap();
    assert_eq!(second.items.len(), 8);
    let ids: Vec<u64> = first
        .events()
        .iter()
        .chain(second.events().iter())
        .map(|event| event.event_id)
        .collect();
    assert_eq!(ids, (0..40).collect::<Vec<u64>>());
    let third = p.bob.receive(0).await.unwrap();
    assert!(third.events().is_empty() && third.redelivered.is_empty());
    assert_eq!(p.bob.delivery_cursor(), 40);
}

async fn fuzz_receiver(seed: u64, ops: usize) -> Result<String, String> {
    let mut rng = Xorshift(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_config = config(directory, relay, "+bob", 1);
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let routes = vec![(bob_member.clone(), bob_route.clone())];
    let mut member_now = false;
    let mut sent_group: Vec<Vec<u8>> = Vec::new();
    let mut sent_direct: Vec<Vec<u8>> = Vec::new();
    let mut shown_group: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut shown_direct: Vec<Vec<u8>> = Vec::new();
    let mut lost_events = 0u64;
    let mut log = String::new();
    let mut counter = 0u32;
    let collect = |shown_group: &mut Vec<(u64, Vec<u8>)>,
                   shown_direct: &mut Vec<Vec<u8>>,
                   lost_events: &mut u64,
                   inbound: &Inbound| {
        shown_group.extend(
            inbound
                .events()
                .iter()
                .map(|event| (event.event_id, event.payload.clone())),
        );
        shown_direct.extend(inbound.direct.iter().map(|m| m.plaintext.clone()));
        *lost_events += inbound.lost_events;
    };
    for step in 0..ops {
        if rng.below(100) < 30 {
            let skip = rng.below(3) as usize;
            let mut outcomes = vec![CommitOutcome::Committed; skip];
            let (bad, lands) = match rng.below(3) {
                0 => (CommitOutcome::Failed, false),
                1 => (CommitOutcome::Unknown, false),
                _ => (CommitOutcome::Unknown, true),
            };
            outcomes.push(bad);
            log.push_str(&format!(
                "[{step}: bob fault {bad:?} lands={lands} after {skip}] "
            ));
            bob_store.script(outcomes, lands);
        }
        counter += 1;
        let payload = format!("q{seed}-{counter}").into_bytes();
        let op = rng.below(8);
        match op {
            0 | 1 => {
                if member_now && alice.send_group(&routes, payload.clone()).await.is_ok() {
                    sent_group.push(payload.clone());
                }
            }
            2 => {
                if alice.send_direct(&bob_route, &payload).await.is_ok() {
                    sent_direct.push(payload.clone());
                }
            }
            3 | 4 => match bob.receive(0).await {
                Ok(inbound) => collect(
                    &mut shown_group,
                    &mut shown_direct,
                    &mut lost_events,
                    &inbound,
                ),
                Err(GroupError::Frozen) => {}
                Err(e) => return Err(format!("seed {seed}: bob receive: {e}\n{log}")),
            },
            5 => {
                // Alice toggles Bob's membership.
                let members = if member_now {
                    vec![alice_member.clone()]
                } else {
                    vec![alice_member.clone(), bob_member.clone()]
                };
                let next = alice.next_roster(members).unwrap();
                if alice.install_roster(next, &routes, None, 0).await.is_ok() {
                    member_now = !member_now;
                }
            }
            6 => {
                drop(std::mem::replace(
                    &mut bob,
                    restart(&bob_config, &bob_store).await,
                ));
                bob.join_group(genesis_of(&alice_member), alice_member.clone())
                    .map_err(|e| format!("join: {e}"))?;
            }
            _ => {
                let _ = bob.recover().await;
            }
        }
        if bob.is_frozen() {
            if rng.below(2) == 0 {
                bob.recover().await.map_err(|e| format!("recover: {e}"))?;
            } else {
                drop(std::mem::replace(
                    &mut bob,
                    restart(&bob_config, &bob_store).await,
                ));
                bob.join_group(genesis_of(&alice_member), alice_member.clone())
                    .map_err(|e| format!("join: {e}"))?;
            }
        }
    }
    bob_store.script([], false);
    if bob.is_frozen() {
        bob.recover()
            .await
            .map_err(|e| format!("final recover: {e}"))?;
    }
    for _ in 0..8 {
        match bob.receive(0).await {
            Ok(inbound) => collect(
                &mut shown_group,
                &mut shown_direct,
                &mut lost_events,
                &inbound,
            ),
            Err(e) => return Err(format!("seed {seed}: final receive: {e}\n{log}")),
        }
    }
    // A group event may be offered again (after a restart, or after a call that
    // failed), but always with the ID it had; a direct message is shown at most
    // once (0132).
    for (id, payload) in &shown_group {
        if shown_group
            .iter()
            .any(|(other_id, other)| other == payload && other_id != id)
        {
            return Err(format!(
                "seed {seed}: one group message under two event IDs: {:?}\n{log}",
                String::from_utf8_lossy(payload)
            ));
        }
        if !sent_group.contains(payload) {
            return Err(format!(
                "seed {seed}: bob was shown a group message never sent: {:?}\n{log}",
                String::from_utf8_lossy(payload)
            ));
        }
    }
    let mut sorted = shown_direct.clone();
    sorted.sort();
    let before = sorted.len();
    sorted.dedup();
    if sorted.len() != before {
        return Err(format!(
            "seed {seed}: a direct message was delivered twice {shown_direct:?}\n{log}"
        ));
    }
    for payload in &shown_direct {
        if !sent_direct.contains(payload) {
            return Err(format!(
                "seed {seed}: bob was shown a direct message never sent: {:?}\n{log}",
                String::from_utf8_lossy(payload)
            ));
        }
    }
    // No group message is lost. This is the invariant 0144 adds: before it, an
    // event committed by a call that then failed, or by an unknown write that
    // landed, was never shown.
    let missing_group: Vec<_> = sent_group
        .iter()
        .filter(|payload| !shown_group.iter().any(|(_, shown)| shown == *payload))
        .collect();
    if !missing_group.is_empty() {
        return Err(format!(
            "seed {seed}: group messages never shown: {:?}\n{log}",
            missing_group
                .iter()
                .map(|m| String::from_utf8_lossy(m).to_string())
                .collect::<Vec<_>>()
        ));
    }
    if lost_events != 0 {
        return Err(format!(
            "seed {seed}: {lost_events} events were reported lost\n{log}"
        ));
    }
    // A direct message is committed once and handed over once; the documented
    // window loses at most one per write that landed while it was in doubt.
    let missing_direct = sent_direct
        .iter()
        .filter(|payload| !shown_direct.contains(payload))
        .count();
    let landed = bob_store.0.lock().unwrap().landed_unknown as usize;
    if missing_direct > landed {
        return Err(format!(
            "seed {seed}: {missing_direct} direct messages missing but only {landed} unknown writes landed\n{log}"
        ));
    }
    // Bob's coordinator agrees with the durable snapshot.
    let durable = bob_store.durable().unwrap();
    if bob.snapshot != durable {
        return Err(format!(
            "seed {seed}: bob's live snapshot differs from the durable one\n{log}"
        ));
    }
    Ok(format!(
        "{log} | missing_direct={missing_direct} landed={landed}"
    ))
}

#[tokio::test]
async fn randomised_receiver_fault_schedule() {
    let seeds: u64 = std::env::var("GROUP_FAULT_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let ops: usize = std::env::var("GROUP_FAULT_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let base: u64 = std::env::var("GROUP_FAULT_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let mut failures = Vec::new();
    for seed in base..base + seeds {
        if let Err(e) = fuzz_receiver(seed, ops).await {
            failures.push(e);
        }
    }
    for f in &failures {
        println!("FAIL {f}");
    }
    println!(
        "receiver fuzz {seeds} seeds x {ops} ops from base {base}: {} failures",
        failures.len()
    );
    assert!(failures.is_empty());
}

/// (alice, bob, bob_store, bob_member, bob_route, alice_store)
async fn duo_with_group_bob() -> (
    GroupClient,
    GroupClient,
    SharedStore,
    Member,
    DeviceAddr,
    SharedStore,
) {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    (alice, bob, bob_store, bob_member, bob_route, alice_store)
}
