//! The durable root under the coordinator (decisions 0132, 0134, 0143): direct
//! messages between group commits, a restart at every point of an interleaving,
//! an in-doubt write during a direct message, a client whose state is not the
//! snapshot's, a second coordinator on one store, a recovery that fails, and
//! randomised fault schedules on the sending side. Every test drives
//! `GroupClient` against the in-process directory and relay with the real
//! provider. `GROUP_FAULT_SEEDS`, `GROUP_FAULT_OPS` and `GROUP_FAULT_BASE` tune
//! the randomised schedule (defaults 40 seeds of 30 operations from seed 1).

use super::*;
use crate::group_operations::{commit_logical_intent, prepare_outbox_group_recipient};

struct Duo {
    directory: SocketAddr,
    relay: SocketAddr,
    alice: GroupClient,
    alice_store: SharedStore,
    alice_config: Config,
    bob: DefaultClient,
    bob_member: Member,
    bob_route: DeviceAddr,
}

async fn duo() -> Duo {
    let (directory, relay) = start_server().await;
    let alice_config = config(directory, relay, "+alice", 1);
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let mut bob = plain(directory, relay, "+bob").await;
    let bob_member = member_of(&bob);
    let bob_route = bob.address().clone();
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    assert_eq!(bob.receive().await.unwrap().len(), 1);
    Duo {
        directory,
        relay,
        alice,
        alice_store,
        alice_config,
        bob,
        bob_member,
        bob_route,
    }
}

impl Duo {
    async fn restart_alice(&mut self) {
        let alice = std::mem::replace(
            &mut self.alice,
            // placeholder is never used: replaced immediately below
            coordinator(
                self.directory,
                self.relay,
                "+placeholder",
                &SharedStore::default(),
            )
            .await,
        );
        drop(alice);
        self.alice = restart(&self.alice_config, &self.alice_store).await;
        self.alice.create_group(gid()).unwrap();
    }

    async fn group(&mut self, text: &str) {
        self.alice
            .send_group(
                &[(self.bob_member.clone(), self.bob_route.clone())],
                text.as_bytes().to_vec(),
            )
            .await
            .unwrap();
    }

    async fn dm(&mut self, text: &str) {
        self.alice
            .send_direct(&self.bob_route.clone(), text.as_bytes())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn restart_at_every_point_of_a_dm_group_interleaving_reuses_no_ratchet_position() {
    // ops: 0 group, 1 dm, 2 group, 3 dm, 4 group; restart after op i (or never).
    for restart_after in [None, Some(0), Some(1), Some(2), Some(3), Some(4)] {
        let mut d = duo().await;
        let ops: [(&str, bool); 5] = [
            ("g0", true),
            ("d0", false),
            ("g1", true),
            ("d1", false),
            ("g2", true),
        ];
        for (i, (text, is_group)) in ops.iter().enumerate() {
            if *is_group {
                d.group(text).await;
            } else {
                d.dm(text).await;
            }
            if restart_after == Some(i) {
                d.restart_alice().await;
            }
        }
        let got = d.bob.drain().await.unwrap();
        println!(
            "restart_after={restart_after:?} bob received {} of 5",
            got.len()
        );
        assert_eq!(got.len(), 5, "restart_after={restart_after:?}");
        let dms: Vec<_> = got
            .iter()
            .filter(|m| m.kind == MessageKind::Direct)
            .map(|m| m.plaintext.clone())
            .collect();
        assert_eq!(dms, vec![b"d0".to_vec(), b"d1".to_vec()]);
    }
}

#[tokio::test]
async fn a_dm_while_a_group_preparation_is_pending_then_restart_delivers_both() {
    let mut d = duo().await;
    // Prepare (encrypt and commit, do not dispatch) a group message to Bob.
    let id = {
        let GroupClient {
            client,
            store,
            snapshot,
            group,
            ..
        } = &mut d.alice;
        let state = group.as_mut().unwrap();
        let view = state.view.as_ref().unwrap();
        let send = LogicalSend::new(
            view.roster(),
            *view.digest(),
            state.local.clone(),
            state
                .outbox
                .next_sequence(view.roster().revision, &state.local)
                .unwrap(),
            vec![d.bob_member.clone()],
            b"prepared g".to_vec(),
        )
        .unwrap();
        let id = send.id.clone();
        commit_logical_intent(store, snapshot, &mut state.outbox, send).unwrap();
        prepare_outbox_group_recipient(
            client,
            store,
            snapshot,
            &mut state.outbox,
            &id,
            &d.bob_member,
            &d.bob_route,
        )
        .await
        .unwrap();
        id
    };
    // A DM to the same member takes the next ratchet position and is committed.
    d.dm("dm after prepare").await;
    // Crash and restart from the snapshot; then drive the pending send.
    d.restart_alice().await;
    let driven = d
        .alice
        .dispatch_pending_group_sends(&[(d.bob_member.clone(), d.bob_route.clone())])
        .await
        .unwrap();
    assert_eq!(driven, 1);
    let state = d.alice.group.as_ref().unwrap();
    assert_eq!(
        state.outbox.send(&id).unwrap().recipients()[0].disposition,
        RecipientDisposition::RelayAccepted
    );
    // A later group message and DM after the restart still work.
    d.group("g after").await;
    d.dm("dm after").await;
    let got = d.bob.drain().await.unwrap();
    println!(
        "bob received {} of 4 (prepared group, dm, group, dm)",
        got.len()
    );
    assert_eq!(got.len(), 4);
}

#[tokio::test]
async fn an_unknown_write_during_a_dm_never_reuses_a_position() {
    for lands in [false, true] {
        let mut d = duo().await;
        d.group("g0").await;
        d.alice_store.script([CommitOutcome::Unknown], lands);
        let bob_route = d.bob_route.clone();
        let failed = d.alice.send_direct(&bob_route, b"d-in-doubt").await;
        assert!(matches!(failed, Err(GroupError::Frozen)), "{failed:?}");
        // Nothing may have been sent for the DM whose commit is in doubt.
        assert_eq!(
            d.bob.drain().await.unwrap().len(),
            1,
            "lands={lands}: only g0"
        );
        // Two recoveries: in process, then crash-restart, then more traffic.
        d.alice.recover().await.unwrap();
        d.dm("d-after-recover").await;
        d.restart_alice().await;
        d.group("g1").await;
        d.dm("d-after-restart").await;
        let got = d.bob.drain().await.unwrap();
        println!(
            "lands={lands} bob received {} of 3 after the first drain",
            got.len()
        );
        assert_eq!(got.len(), 3, "lands={lands}");
    }
}

#[tokio::test]
async fn a_second_coordinator_on_one_store_is_fenced_and_no_position_is_reused() {
    // Two processes on one device (an app and an extension) each open the
    // store. The second writer's commit is refused (0143): it never sends the
    // ciphertext it encrypted at the position the first writer used.
    let mut d = duo().await;
    d.dm("warm-up").await;
    assert_eq!(d.bob.drain().await.unwrap().len(), 1);
    let generation_before = d.alice_store.durable().unwrap().generation;
    // Second coordinator, connected from the snapshot the first one wrote.
    let mut second = restart(&d.alice_config, &d.alice_store).await;
    d.dm("from the first").await;
    let published = d.alice_store.durable().unwrap();
    assert_eq!(published.generation, generation_before + 1);
    let bob_route = d.bob_route.clone();
    let refused = second.send_direct(&bob_route, b"from the second").await;
    assert!(matches!(refused, Err(GroupError::Frozen)), "{refused:?}");
    assert!(second.is_frozen());
    assert_eq!(
        d.alice_store.durable().unwrap(),
        published,
        "the second writer's commit did not overwrite the first's"
    );
    let got = d.bob.drain().await.unwrap();
    let texts: Vec<_> = got
        .iter()
        .map(|m| String::from_utf8_lossy(&m.plaintext).to_string())
        .collect();
    assert_eq!(texts, ["from the first"], "the fenced send went nowhere");
    // Recovery adopts what the store holds now; the next send is at a new
    // position and arrives.
    second.recover().await.unwrap();
    second
        .send_direct(&bob_route, b"after recovery")
        .await
        .unwrap();
    let got = d.bob.drain().await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].plaintext, b"after recovery");
    assert_eq!(
        d.alice_store.durable().unwrap().generation,
        generation_before + 2
    );
}

#[tokio::test]
async fn open_refuses_a_client_whose_state_is_behind_the_snapshot() {
    let mut d = duo().await;
    // An older copy of the client's state, as an app that also keeps its own
    // state blob (or restores a backup) would hold.
    let older = d.alice.client.export_state().await.unwrap();
    d.dm("first, after the backup").await;
    assert_eq!(d.bob.drain().await.unwrap().len(), 1);
    let before = d.alice_store.durable().unwrap();
    drop(std::mem::replace(
        &mut d.alice,
        coordinator(
            d.directory,
            d.relay,
            "+placeholder",
            &SharedStore::default(),
        )
        .await,
    ));
    // Reconnect from the OLDER state but hand the coordinator the NEWER store.
    let client = DefaultClient::connect_with_state(&d.alice_config, &older)
        .await
        .unwrap();
    let refused = GroupClient::open(client, d.alice_store.clone()).await;
    assert!(
        matches!(refused, Err(GroupError::StateMismatch)),
        "{:?}",
        refused.err()
    );
    assert_eq!(
        d.alice_store.durable().unwrap(),
        before,
        "a refused open writes nothing"
    );
    // The remedy the documentation gives works, and the position is not reused.
    let mut alice = restart(&d.alice_config, &d.alice_store).await;
    alice.create_group(gid()).unwrap();
    alice
        .send_direct(&d.bob_route.clone(), b"second, next position")
        .await
        .unwrap();
    let got = d.bob.drain().await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].plaintext, b"second, next position");
}

#[tokio::test]
async fn open_refuses_a_client_whose_state_is_ahead_of_the_snapshot() {
    let mut d = duo().await;
    d.dm("in the snapshot").await;
    assert_eq!(d.bob.drain().await.unwrap().len(), 1);
    let before = d.alice_store.durable().unwrap();
    drop(std::mem::replace(
        &mut d.alice,
        coordinator(
            d.directory,
            d.relay,
            "+placeholder",
            &SharedStore::default(),
        )
        .await,
    ));
    // The client is connected from the snapshot and then used through the plain
    // API before it is wrapped: it consumes a ratchet position the snapshot has
    // never seen.
    let state = recovered_provider_state(&mut d.alice_store.clone())
        .unwrap()
        .unwrap();
    let mut client = DefaultClient::connect_with_state(&d.alice_config, &state)
        .await
        .unwrap();
    client
        .send(&d.bob_route.clone(), b"plain send")
        .await
        .unwrap();
    assert_eq!(d.bob.drain().await.unwrap().len(), 1);
    let refused = GroupClient::open(client, d.alice_store.clone()).await;
    assert!(
        matches!(refused, Err(GroupError::StateMismatch)),
        "{:?}",
        refused.err()
    );
    assert_eq!(d.alice_store.durable().unwrap(), before);
}

#[tokio::test]
async fn open_accepts_a_client_connected_from_the_snapshot_with_several_peers() {
    // The comparison is only usable if the export is a function of the state:
    // with several peers the order of the sessions once depended on a hash set.
    let (directory, relay) = start_server().await;
    let config = config(directory, relay, "+alice", 1);
    let store = SharedStore::default();
    let mut alice = GroupClient::open(
        DefaultClient::connect(&config).await.unwrap(),
        store.clone(),
    )
    .await
    .unwrap();
    for name in ["+bob", "+carol", "+dave", "+erin"] {
        let peer = plain(directory, relay, name).await;
        alice.send_direct(peer.address(), b"hello").await.unwrap();
    }
    drop(alice);
    for round in 0..12 {
        let opened = restart_result(&config, &store).await;
        assert!(opened.is_ok(), "round {round}: {:?}", opened.err());
    }
}

async fn restart_result(config: &Config, store: &SharedStore) -> Result<GroupClient, GroupError> {
    let state = recovered_provider_state(&mut store.clone())
        .unwrap()
        .expect("the store holds a snapshot");
    let client = DefaultClient::connect_with_state(config, &state)
        .await
        .unwrap();
    GroupClient::open(client, store.clone()).await
}

#[tokio::test]
async fn open_refuses_a_snapshot_with_no_provider_state_and_one_of_another_identity() {
    let (directory, relay) = start_server().await;
    let config = config(directory, relay, "+alice", 1);
    let store = SharedStore::default();
    let alice = GroupClient::open(
        DefaultClient::connect(&config).await.unwrap(),
        store.clone(),
    )
    .await
    .unwrap();
    let state = alice.client.export_state().await.unwrap();
    drop(alice);
    let stranger = GroupClient::open(plain(directory, relay, "+carol").await, store.clone()).await;
    assert!(
        matches!(stranger, Err(GroupError::Recovery)),
        "{:?}",
        stranger.err()
    );
    store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .provider_state = Vec::new();
    let client = DefaultClient::connect_with_state(&config, &state)
        .await
        .unwrap();
    let empty = GroupClient::open(client, store.clone()).await;
    assert!(
        matches!(empty, Err(GroupError::Recovery)),
        "{:?}",
        empty.err()
    );
}

#[tokio::test]
async fn a_first_contact_dm_whose_commit_is_in_doubt_still_reaches_the_peer_after_recovery() {
    for (label, lands, restart_instead) in [
        ("unknown, not landed, in-process recover", false, false),
        ("unknown, landed, in-process recover", true, false),
        ("unknown, landed, restart", true, true),
    ] {
        let (directory, relay) = start_server().await;
        let alice_config = config(directory, relay, "+alice", 1);
        let alice_store = SharedStore::default();
        let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
        let mut bob = plain(directory, relay, "+bob").await;
        let bob_route = bob.address().clone();
        alice_store.script([CommitOutcome::Unknown], lands);
        let first = alice.send_direct(&bob_route, b"first contact 1").await;
        assert!(
            matches!(first, Err(GroupError::Frozen)),
            "{label}: {first:?}"
        );
        if restart_instead {
            drop(alice);
            alice = restart(&alice_config, &alice_store).await;
        } else {
            alice.recover().await.unwrap();
        }
        alice
            .send_direct(&bob_route, b"first contact 2")
            .await
            .unwrap();
        let got = bob.drain().await.unwrap();
        println!(
            "{label}: bob received {:?}",
            got.iter()
                .map(|m| String::from_utf8_lossy(&m.plaintext).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(got.len(), 1, "{label}");
        // And the conversation goes on in both directions.
        alice.send_direct(&bob_route, b"third").await.unwrap();
        assert_eq!(bob.drain().await.unwrap().len(), 1, "{label}");
        bob.send(alice.address(), b"reply").await.unwrap();
        let back = alice.receive(0).await.unwrap();
        assert_eq!(back.direct.len(), 1, "{label}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dm_and_group_sends_from_two_tasks_reuse_no_position() {
    let d = duo().await;
    let Duo {
        alice,
        alice_store,
        alice_config,
        mut bob,
        bob_member,
        bob_route,
        directory,
        relay,
    } = d;
    let alice = Arc::new(tokio::sync::Mutex::new(alice));
    let mut tasks = Vec::new();
    for worker in 0..2usize {
        let alice = alice.clone();
        let (bob_member, bob_route) = (bob_member.clone(), bob_route.clone());
        tasks.push(tokio::spawn(async move {
            for i in 0..25usize {
                let mut a = alice.lock().await;
                if worker == 0 {
                    a.send_direct(&bob_route, format!("dm-{i}").as_bytes())
                        .await
                        .unwrap();
                } else {
                    a.send_group(
                        &[(bob_member.clone(), bob_route.clone())],
                        format!("g-{i}").into_bytes(),
                    )
                    .await
                    .unwrap();
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let got = bob.drain().await.unwrap();
    println!("bob received {} of 50 concurrent sends", got.len());
    assert_eq!(got.len(), 50);
    // Restart from the store and go on: still no reuse.
    drop(alice);
    let mut again = restart(&alice_config, &alice_store).await;
    again.create_group(gid()).unwrap();
    again.send_direct(&bob_route, b"after").await.unwrap();
    assert_eq!(bob.drain().await.unwrap().len(), 1);
    let _ = (directory, relay);
}

// ---------------------------------------------------------------------------
// recover() keeps the freeze until it has succeeded (0143).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_recovery_that_fails_after_a_store_latch_keeps_the_coordinator_frozen() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let routes = vec![(bob_member.clone(), route(&bob))];
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();

    // `install_roster` prepares a control (the ratchet advances in memory), its
    // commit fails and the store latches; the coordinator itself is not
    // poisoned, only the store is latched.
    alice_store.script([CommitOutcome::Failed], false);
    assert!(matches!(
        alice.install_roster(r1.clone(), &routes, None, 0).await,
        Err(GroupError::Frozen)
    ));
    assert!(alice.is_frozen());

    // The durable snapshot can be read, but its provider state cannot be
    // restored: the recovery fails after the store latch was lifted.
    let good = alice_store.durable().unwrap();
    alice_store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .provider_state = vec![0xEE; 8];
    assert!(alice.recover().await.is_err());
    assert!(
        alice.is_frozen(),
        "a failed recovery must not lift the freeze"
    );
    assert!(matches!(
        alice.install_roster(r1.clone(), &routes, None, 0).await,
        Err(GroupError::Frozen)
    ));
    // Repeating it once the store is readable succeeds and unfreezes.
    alice_store.0.lock().unwrap().snapshot = Some(good);
    alice.recover().await.unwrap();
    assert!(!alice.is_frozen());
    let install = alice.install_roster(r1, &routes, None, 0).await.unwrap();
    assert_eq!(install.delivered.len(), 1);
}

#[tokio::test]
async fn a_recovery_from_a_store_that_holds_nothing_keeps_the_coordinator_frozen() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    let bob = plain(directory, relay, "+bob").await;
    store.script([CommitOutcome::Failed], false);
    assert!(matches!(
        alice.send_direct(bob.address(), b"one").await,
        Err(GroupError::Frozen)
    ));
    store.0.lock().unwrap().snapshot = None;
    assert!(matches!(alice.recover().await, Err(GroupError::Recovery)));
    assert!(alice.is_frozen());
}

// ---------------------------------------------------------------------------
// Randomised crash/fault schedule over the sender: sends, dispatches, direct
// messages, restarts and in-place recoveries, with a commit that fails or is in
// doubt now and then. Invariants checked at the end, with faults off:
//   - no event is shown to Bob twice
//   - every logical send Alice's durable outbox calls relay-accepted was shown
//   - every direct send that returned Ok arrived
//   - nothing is left prepared, pending or handed off after the drive loop
// ---------------------------------------------------------------------------

pub(super) struct Xorshift(pub(super) u64);

impl Xorshift {
    pub(super) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub(super) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

async fn fuzz_sender(seed: u64, ops: usize) -> Result<String, String> {
    let mut rng = Xorshift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let (directory, relay) = start_server().await;
    let alice_config = config(directory, relay, "+alice", 1);
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();

    let routes = vec![(bob_member.clone(), bob_route.clone())];
    let mut shown: Vec<Vec<u8>> = Vec::new();
    let mut dms_ok: Vec<Vec<u8>> = Vec::new();
    let mut log = String::new();
    let mut counter = 0u32;
    for step in 0..ops {
        if rng.below(100) < 30 {
            let skip = rng.below(4) as usize;
            let mut outcomes = vec![CommitOutcome::Committed; skip];
            let (bad, lands) = match rng.below(3) {
                0 => (CommitOutcome::Failed, false),
                1 => (CommitOutcome::Unknown, false),
                _ => (CommitOutcome::Unknown, true),
            };
            outcomes.push(bad);
            log.push_str(&format!(
                "[{step}: fault {bad:?} lands={lands} after {skip}] "
            ));
            alice_store.script(outcomes, lands);
        }
        counter += 1;
        let payload = format!("p{seed}-{counter}").into_bytes();
        let op = rng.below(7);
        let result: Result<(), GroupError> = match op {
            0 | 1 => alice.send_group(&routes, payload.clone()).await.map(|_| ()),
            2 => alice
                .dispatch_pending_group_sends(&routes)
                .await
                .map(|_| ()),
            3 => {
                let r = alice.send_direct(&bob_route, &payload).await;
                if r.is_ok() {
                    dms_ok.push(payload.clone());
                }
                r
            }
            4 => {
                let inbound = match bob.receive(0).await {
                    Ok(inbound) => inbound,
                    Err(e) => return Err(format!("bob: {e}")),
                };
                shown.extend(inbound.events().iter().map(|e| e.payload.clone()));
                shown.extend(inbound.direct.iter().map(|m| m.plaintext.clone()));
                Ok(())
            }
            5 => {
                drop(std::mem::replace(
                    &mut alice,
                    restart(&alice_config, &alice_store).await,
                ));
                if let Err(e) = alice.create_group(gid()) {
                    return Err(format!("create: {e}"));
                }
                Ok(())
            }
            _ => alice.recover().await,
        };
        log.push_str(&format!(
            "{step}:op{op}:{} ",
            if result.is_ok() { "ok" } else { "err" }
        ));
        if alice.is_frozen() {
            if rng.below(2) == 0 {
                alice.recover().await.map_err(|e| format!("recover: {e}"))?;
            } else {
                drop(std::mem::replace(
                    &mut alice,
                    restart(&alice_config, &alice_store).await,
                ));
                alice
                    .create_group(gid())
                    .map_err(|e| format!("create: {e}"))?;
            }
        }
    }
    // Faults off; bring Alice fully up; drive everything.
    alice_store.script([], false);
    if alice.is_frozen() {
        alice
            .recover()
            .await
            .map_err(|e| format!("final recover: {e}"))?;
    }
    for _ in 0..6 {
        alice
            .dispatch_pending_group_sends(&routes)
            .await
            .map_err(|e| format!("final dispatch: {e}"))?;
    }
    for _ in 0..6 {
        let inbound = bob.receive(0).await.map_err(|e| format!("bob: {e}"))?;
        shown.extend(inbound.events().iter().map(|e| e.payload.clone()));
        shown.extend(inbound.direct.iter().map(|m| m.plaintext.clone()));
    }
    let mut sorted = shown.clone();
    sorted.sort();
    let before = sorted.len();
    sorted.dedup();
    if sorted.len() != before {
        return Err(format!(
            "seed {seed}: duplicate delivery. shown={shown:?}\n{log}"
        ));
    }
    let durable = alice_store.durable().unwrap();
    let outbox = recover_group_outbox(&durable, gid()).map_err(|_| "recover outbox".to_string())?;
    let live = &alice.group.as_ref().unwrap().outbox;
    if &outbox != live {
        return Err(format!(
            "seed {seed}: live outbox differs from the durable one\n{log}"
        ));
    }
    for send in outbox.sends() {
        let progress = &send.recipients()[0];
        match progress.disposition {
            RecipientDisposition::RelayAccepted => {
                // Its payload is a private detail of the intent; find it by context.
                let context = send.application_context(&bob_member).unwrap();
                if !shown.contains(&context.payload) {
                    return Err(format!(
                        "seed {seed}: relay-accepted send {:?} never shown to bob. shown={:?}\n{log}",
                        String::from_utf8_lossy(&context.payload),
                        shown
                            .iter()
                            .map(|m| String::from_utf8_lossy(m).to_string())
                            .collect::<Vec<_>>()
                    ));
                }
            }
            RecipientDisposition::ExhaustedUnknown => {}
            other => {
                return Err(format!(
                    "seed {seed}: a send is stuck at {other:?} after the drive loop\n{log}"
                ));
            }
        }
    }
    for dm in &dms_ok {
        if !shown.contains(dm) {
            return Err(format!(
                "seed {seed}: an acknowledged direct message never arrived: {:?}\n{log}",
                String::from_utf8_lossy(dm)
            ));
        }
    }
    Ok(log)
}

#[tokio::test]
async fn randomised_sender_fault_schedule() {
    let seeds: u64 = std::env::var("GROUP_FAULT_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let ops: usize = std::env::var("GROUP_FAULT_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let mut failures = Vec::new();
    for seed in 1..=seeds {
        match fuzz_sender(seed, ops).await {
            Ok(_) => {}
            Err(e) => failures.push(e),
        }
    }
    for f in &failures {
        println!("FAIL {f}");
    }
    println!("{} seeds x {ops} ops, {} failures", seeds, failures.len());
    assert!(failures.is_empty());
}

#[tokio::test]
async fn long_running_use_keeps_every_collection_within_its_literal_bound() {
    // 300 group messages of 1,000 bytes and 60 direct messages each way, with a
    // roster change every 50 messages (removing and re-adding Bob).
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let bob_route = bob.address().clone();
    let stats = |label: &str, s: &SharedStore| {
        let snap = s.durable().unwrap();
        println!(
            "{label}: bytes={} provider={} app={} outbox_bytes={} inbox_bytes={} controls_bytes={} outbox={} inbox={} dedup={} controls={} generation={}",
            snap.encode().unwrap().len(),
            snap.provider_state.len(),
            snap.application_state.len(),
            snap.outbox.iter().map(Vec::len).sum::<usize>(),
            snap.inbox.iter().map(Vec::len).sum::<usize>(),
            snap.group_controls.iter().map(Vec::len).sum::<usize>(),
            snap.outbox.len(),
            snap.inbox.len(),
            snap.dedup.len(),
            snap.group_controls.len(),
            snap.generation
        );
        snap
    };
    let mut roster_revision = 0;
    let mut bob_in = false;
    let started = std::time::Instant::now();
    let mut worst: (usize, usize, usize, usize) = (0, 0, 0, 0);
    let mut delivered = 0usize;
    for i in 0..300usize {
        if i % 50 == 0 {
            let members = if bob_in {
                vec![alice_member.clone()]
            } else {
                vec![alice_member.clone(), bob_member.clone()]
            };
            let next = alice.next_roster(members).unwrap();
            let install = alice
                .install_roster(next, &[(bob_member.clone(), bob_route.clone())], None, 0)
                .await
                .unwrap();
            assert!(install.pending.is_empty());
            bob_in = !bob_in;
            roster_revision += 1;
            bob.receive(0).await.unwrap();
        }
        if bob_in {
            alice
                .send_group(&[(bob_member.clone(), bob_route.clone())], vec![7u8; 1000])
                .await
                .unwrap();
            let inbound = bob.receive(0).await.unwrap();
            delivered += inbound.events().len();
            alice.send_direct(&bob_route, b"dm").await.unwrap();
            bob.receive(0).await.unwrap();
        }
        for s in [&alice_store, &bob_store] {
            let snap = s.durable().unwrap();
            worst = (
                worst.0.max(snap.outbox.len()),
                worst.1.max(snap.inbox.len()),
                worst.2.max(snap.dedup.len()),
                worst.3.max(snap.group_controls.len()),
            );
        }
        if i % 100 == 99 {
            stats("alice", &alice_store);
            stats("bob", &bob_store);
        }
    }
    println!(
        "300 iterations, {roster_revision} roster changes, {delivered} events delivered, {:?} elapsed; worst lengths outbox={} inbox={} dedup={} controls={}",
        started.elapsed(),
        worst.0,
        worst.1,
        worst.2,
        worst.3
    );
    assert!(worst.1 <= 64 && worst.2 <= 512 && worst.3 <= 64);
}
