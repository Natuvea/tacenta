//! A fault at every commit of a held-control drain (decisions 0142, 0143), and a randomised
//! receiver schedule that checks what a consumer relies on (decision 0144): an event that a
//! completed call handed over and a later call acknowledged is never shown again, event IDs
//! ascend inside a call and across calls, and nothing is lost silently. A dropped `receive` future
//! (a timeout around a wait) does not desynchronise the relay connection or lose an event (0148).
//!
//! `GROUP_SCHEDULE_SEEDS`, `GROUP_SCHEDULE_OPS` and `GROUP_SCHEDULE_BASE` tune the schedule
//! (defaults 12, 50 and 1). The second test makes a registered peer flood junk payloads between
//! calls, so that events can be evicted before they are handed over.

use super::durable_root::Xorshift;
use super::held_roster_controls_guards::{chain_after, send_control};
use super::*;

struct Held {
    authority: DefaultClient,
    bob: GroupClient,
    bob_store: SharedStore,
    bob_config: Config,
    bob_route: DeviceAddr,
    genesis: Roster,
    chain: Vec<Roster>,
}

/// A coordinator that joined from the genesis of an authority's group, and the chain of `count`
/// rosters the authority would send it.
async fn held_setup(count: u64) -> Held {
    let (directory, relay) = start_server().await;
    let authority = plain(directory, relay, "+authority").await;
    let authority_member = member_of(&authority);
    let bob_store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &bob_store).await;
    let bob_route = route(&bob);
    let bob_member = bob.member().unwrap();
    let genesis = genesis_of(&authority_member);
    bob.join_group(genesis.clone(), authority_member.clone())
        .unwrap();
    let mut members = vec![authority_member.clone(), bob_member];
    members.sort_by(|a, b| a.canonical_cmp(b));
    let chain = chain_after(&genesis, count, &members);
    Held {
        authority,
        bob,
        bob_store,
        bob_config: config(directory, relay, "+bob", 1),
        bob_route,
        genesis,
        chain,
    }
}

async fn reconnect(h: &mut Held) {
    let authority_member = member_of(&h.authority);
    let fresh = restart(&h.bob_config, &h.bob_store).await;
    drop(std::mem::replace(&mut h.bob, fresh));
    h.bob
        .join_group(h.genesis.clone(), authority_member)
        .unwrap();
}

async fn deliver_and_receive(h: &mut Held, revision_index: usize) {
    let roster = h.chain[revision_index].clone();
    send_control(&mut h.authority, &h.bob_route, &roster).await;
    match h.bob.receive(0).await {
        Ok(_) | Err(GroupError::Frozen) => {}
        Err(other) => panic!("receive: {other:?}"),
    }
    if h.bob.is_frozen() {
        h.bob.recover().await.unwrap();
    }
}

/// Five controls arrive in an order that holds most of them, and a store fault of each kind
/// (failed, unknown and not landed, unknown and landed) strikes at each of the first twelve
/// commits. After the fault is cleared and the coordinator recovered, it is at revision 5 with
/// nothing held, and it is again after a restart. 108 runs.
#[tokio::test]
async fn a_fault_at_every_commit_of_a_reverse_order_drain_still_converges() {
    let mut failures = Vec::new();
    let mut runs = 0;
    for order in [
        vec![4usize, 3, 2, 1, 0],
        vec![1, 4, 3, 2, 0],
        vec![2, 0, 4, 3, 1],
    ] {
        for k in 0..12usize {
            for (bad, lands) in [
                (CommitOutcome::Failed, false),
                (CommitOutcome::Unknown, false),
                (CommitOutcome::Unknown, true),
            ] {
                runs += 1;
                let mut h = held_setup(5).await;
                let mut outcomes = vec![CommitOutcome::Committed; k];
                outcomes.push(bad);
                h.bob_store.script(outcomes, lands);
                for &i in &order {
                    deliver_and_receive(&mut h, i).await;
                }
                h.bob_store.script([], false);
                for _ in 0..3 {
                    let _ = h.bob.receive(0).await;
                    if h.bob.is_frozen() {
                        h.bob.recover().await.unwrap();
                    }
                }
                let live = h.bob.roster().unwrap().revision;
                let held = h.bob.held_roster_controls();
                reconnect(&mut h).await;
                let restarted = h.bob.roster().unwrap().revision;
                let held_after = h.bob.held_roster_controls();
                if live != 5 || !held.is_empty() || restarted != 5 || !held_after.is_empty() {
                    failures.push(format!(
                        "order {order:?} k={k} {bad:?} lands={lands}: live {live} held {held:?} restarted {restarted} held {held_after:?}"
                    ));
                }
            }
        }
    }
    assert_eq!(runs, 108);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Alice is the authority of a group whose roster admits Bob, and Bob has installed it.
struct Duo {
    alice: GroupClient,
    bob: GroupClient,
    bob_store: SharedStore,
    bob_member: Member,
    bob_route: DeviceAddr,
    bob_config: Config,
    directory: SocketAddr,
    relay: SocketAddr,
}

async fn duo() -> Duo {
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
    Duo {
        alice,
        bob,
        bob_store,
        bob_member,
        bob_route,
        bob_config: config(directory, relay, "+bob", 1),
        directory,
        relay,
    }
}

/// One seed of the schedule. Bob's store fails, gets stuck and recovers at random; Bob restarts;
/// Alice sends and toggles Bob's membership; with `junk` a registered peer floods junk payloads.
/// A consumer model tracks what every completed `receive` handed over and what a later call or
/// `acknowledge_delivery` acknowledged, and checks that an acknowledged event is never shown
/// again, that IDs ascend strictly inside a call and across two calls with nothing between them,
/// that one payload never has two IDs, that nothing is missing unless a loss was reported, and
/// that Bob's live snapshot equals the durable one at the end.
async fn receiver_schedule(seed: u64, ops: usize, junk: bool) -> Result<(), String> {
    let mut rng = Xorshift(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
    let Duo {
        mut alice,
        mut bob,
        bob_store,
        bob_member,
        bob_route,
        bob_config,
        directory,
        relay,
    } = duo().await;
    let alice_member = alice.member().unwrap();
    let mut mallory = plain(directory, relay, "+mallory").await;
    let routes = vec![(bob_member.clone(), bob_route.clone())];
    let mut member_now = true;
    let mut sent_group: Vec<Vec<u8>> = Vec::new();
    let mut shown: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut acknowledged: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // Event IDs handed over by completed calls and not yet acknowledged.
    let mut handed_over: Vec<u64> = Vec::new();
    let mut lost_reported = 0u64;
    let mut log = String::new();
    let mut counter = 0u32;
    // The largest ID handed over by the previous completed call, while nothing intervened.
    let mut last_max: Option<u64> = None;

    macro_rules! completed_call {
        ($inbound:expr) => {{
            let inbound: &Inbound = $inbound;
            // A completed call acknowledges what every earlier completed call handed over.
            for id in handed_over.drain(..) {
                acknowledged.insert(id);
            }
            lost_reported += inbound.lost_events;
            let ids: Vec<u64> = inbound.events().iter().map(|e| e.event_id).collect();
            if ids.windows(2).any(|w| w[0] >= w[1]) {
                return Err(format!(
                    "seed {seed}: IDs not strictly ascending {ids:?}\n{log}"
                ));
            }
            for event in inbound.events() {
                if acknowledged.contains(&event.event_id) {
                    return Err(format!(
                        "seed {seed}: event {} shown after it was acknowledged\n{log}",
                        event.event_id
                    ));
                }
                shown.push((event.event_id, event.payload.clone()));
            }
            if let (Some(previous), Some(first)) = (last_max, ids.first()) {
                if *first <= previous {
                    return Err(format!(
                        "seed {seed}: first ID {first} after the previous maximum {previous} with no restart or fault between\n{log}"
                    ));
                }
            }
            if let Some(max) = ids.iter().max() {
                last_max = Some(*max);
            }
            handed_over.extend(ids);
            if inbound.frozen {
                last_max = None;
            }
        }};
    }

    for step in 0..ops {
        if rng.below(100) < 25 {
            let skip = rng.below(3) as usize;
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
            bob_store.script(outcomes, lands);
        }
        counter += 1;
        let payload = format!("w{seed}-{counter}").into_bytes();
        match rng.below(9) {
            0 | 1 => {
                if member_now && alice.send_group(&routes, payload.clone()).await.is_ok() {
                    sent_group.push(payload);
                    log.push_str(&format!("[{step}: send] "));
                }
            }
            2..=4 => match bob.receive(0).await {
                Ok(inbound) => {
                    log.push_str(&format!(
                        "[{step}: receive events={:?} redelivered={} lost={}] ",
                        inbound
                            .events()
                            .iter()
                            .map(|e| e.event_id)
                            .collect::<Vec<_>>(),
                        inbound.redelivered.len(),
                        inbound.lost_events
                    ));
                    completed_call!(&inbound);
                }
                Err(GroupError::Frozen) => {
                    log.push_str(&format!("[{step}: receive frozen] "));
                    last_max = None;
                }
                Err(e) => return Err(format!("seed {seed}: receive: {e}\n{log}")),
            },
            5 => match bob.acknowledge_delivery() {
                Ok(()) => {
                    log.push_str(&format!("[{step}: acknowledge] "));
                    for id in handed_over.drain(..) {
                        acknowledged.insert(id);
                    }
                }
                Err(_) => {
                    log.push_str(&format!("[{step}: acknowledge failed] "));
                    last_max = None;
                }
            },
            6 => {
                drop(std::mem::replace(
                    &mut bob,
                    restart(&bob_config, &bob_store).await,
                ));
                bob.join_group(genesis_of(&alice_member), alice_member.clone())
                    .map_err(|e| format!("join: {e}"))?;
                log.push_str(&format!("[{step}: restart] "));
                // A restart forgets what was handed over, so events shown and not yet
                // acknowledged may come back.
                last_max = None;
                handed_over.clear();
            }
            7 => {
                if junk {
                    for _ in 0..(20 + rng.below(30)) {
                        let _ = mallory
                            .send_as(&bob_route, b"junk that is no group payload", Kind::Group)
                            .await;
                    }
                    log.push_str(&format!("[{step}: junk] "));
                } else {
                    let members = if member_now {
                        vec![alice_member.clone()]
                    } else {
                        vec![alice_member.clone(), bob_member.clone()]
                    };
                    let next = alice.next_roster(members).unwrap();
                    if alice.install_roster(next, &routes, None, 0).await.is_ok() {
                        member_now = !member_now;
                        log.push_str(&format!("[{step}: membership now {member_now}] "));
                    }
                }
            }
            _ => {
                if bob.recover().await.is_ok() {
                    log.push_str(&format!("[{step}: recover] "));
                    last_max = None;
                    handed_over.clear();
                }
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
            last_max = None;
            handed_over.clear();
        }
    }
    bob_store.script([], false);
    if bob.is_frozen() {
        bob.recover()
            .await
            .map_err(|e| format!("final recover: {e}"))?;
        last_max = None;
        handed_over.clear();
    }
    for _ in 0..8 {
        match bob.receive(0).await {
            Ok(inbound) => completed_call!(&inbound),
            Err(e) => return Err(format!("seed {seed}: final receive: {e}\n{log}")),
        }
    }
    let missing: Vec<&Vec<u8>> = sent_group
        .iter()
        .filter(|payload| !shown.iter().any(|(_, seen)| seen == *payload))
        .collect();
    if missing.len() as u64 > lost_reported {
        return Err(format!(
            "seed {seed}: {} group messages never shown but only {lost_reported} lost events reported: {:?}\n{log}",
            missing.len(),
            missing
                .iter()
                .map(|m| String::from_utf8_lossy(m).to_string())
                .collect::<Vec<_>>()
        ));
    }
    if !junk && !missing.is_empty() {
        return Err(format!(
            "seed {seed}: messages missing without any junk: {missing:?}\n{log}"
        ));
    }
    for (id, payload) in &shown {
        if shown
            .iter()
            .any(|(other, seen)| seen == payload && other != id)
        {
            return Err(format!(
                "seed {seed}: one payload under two IDs: {:?}\n{log}",
                String::from_utf8_lossy(payload)
            ));
        }
    }
    let durable = bob_store.durable().unwrap();
    if bob.snapshot != durable {
        return Err(format!(
            "seed {seed}: the live snapshot differs from the durable one\n{log}"
        ));
    }
    Ok(())
}

async fn run_schedule(junk: bool) {
    let variable = |name: &str, default: u64| -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    let seeds = variable("GROUP_SCHEDULE_SEEDS", 12);
    let ops = variable("GROUP_SCHEDULE_OPS", 50) as usize;
    let base = variable("GROUP_SCHEDULE_BASE", 1);
    let mut failures = Vec::new();
    for seed in base..base + seeds {
        if let Err(error) = receiver_schedule(seed, ops, junk).await {
            failures.push(error);
        }
    }
    for failure in failures.iter().take(5) {
        println!("FAIL {failure}");
    }
    println!(
        "receiver schedule junk={junk} {seeds} seeds x {ops} ops from base {base}: {} failures",
        failures.len()
    );
    assert!(failures.is_empty());
}

#[tokio::test]
async fn the_receiver_schedule_never_shows_an_acknowledged_event_again() {
    run_schedule(false).await;
}

#[tokio::test]
async fn the_receiver_schedule_under_a_junk_flood_reports_every_loss() {
    run_schedule(true).await;
}

/// A `receive` future dropped after a random time (a timeout around the wait): the next call must
/// not fail, and no event may be lost. Before 0148 a request dropped after its frame was written
/// left its response on the connection, and the next call answered `expected a delivery` or
/// `acknowledgement was not accepted`.
#[tokio::test]
async fn a_cancelled_receive_does_not_break_the_next_call() {
    let Duo {
        mut alice,
        mut bob,
        bob_member,
        bob_route,
        ..
    } = duo().await;
    let routes = vec![(bob_member, bob_route)];
    let mut rng = Xorshift(7);
    let (mut cancelled, mut sent) = (0, Vec::new());
    let mut shown: Vec<Vec<u8>> = Vec::new();
    for attempt in 0..120 {
        let payload = format!("c{attempt}").into_bytes();
        alice.send_group(&routes, payload.clone()).await.unwrap();
        sent.push(payload);
        let micros = 20 + rng.below(3000);
        match tokio::time::timeout(std::time::Duration::from_micros(micros), bob.receive(0)).await {
            Ok(inbound) => {
                shown.extend(inbound.unwrap().events().iter().map(|e| e.payload.clone()))
            }
            Err(_) => {
                cancelled += 1;
                let next = bob.receive(0).await.unwrap_or_else(|error| {
                    panic!("attempt {attempt}: the call after a cancelled one failed: {error:?}")
                });
                shown.extend(next.events().iter().map(|e| e.payload.clone()));
            }
        }
    }
    for _ in 0..3 {
        let inbound = bob.receive(0).await.unwrap();
        shown.extend(inbound.events().iter().map(|e| e.payload.clone()));
    }
    assert!(cancelled > 0, "the schedule cancelled no receive");
    for payload in &sent {
        assert!(
            shown.contains(payload),
            "{} was never shown",
            String::from_utf8_lossy(payload)
        );
    }
}
