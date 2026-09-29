//! The per-size measurement that `tooling/measure-group-chat.sh` runs. It is
//! ignored so that `cargo test` does not run a measurement, and it drives a
//! `GroupClient` over a native file store with real 32-byte identities.

use super::*;

/// A native file store that counts and times its commits, so a probe can say how
/// many whole-snapshot writes one logical send costs.
#[derive(Clone)]
struct CountingFileStore {
    inner: Arc<Mutex<crate::operation_store::FileOperationStore>>,
    commits: Arc<Mutex<usize>>,
}

impl OperationStore for CountingFileStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        *self.commits.lock().unwrap() += 1;
        self.inner.lock().unwrap().commit(snapshot)
    }

    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        self.inner.lock().unwrap().recover()
    }

    // The coordinator commits through `commit_after` (0143). Forward it, and the
    // header read it uses, to the native store so that the measurement is of the
    // native store's own check and not of the provided read-then-write.
    fn durable_generation(&mut self) -> Result<Option<u64>, StoreError> {
        self.inner.lock().unwrap().durable_generation()
    }

    fn commit_after(
        &mut self,
        expected: Option<u64>,
        snapshot: &OperationSnapshot,
    ) -> CommitOutcome {
        *self.commits.lock().unwrap() += 1;
        self.inner.lock().unwrap().commit_after(expected, snapshot)
    }
}

/// The per-size measurement `tooling/measure-group-chat.sh` runs, one process
/// per member count. It reads `GROUP_SCALE_MEMBERS` (2, 3 or 8; every size when
/// unset), builds that many real clients with 32-byte identities, has the
/// authority send one 1,000-byte logical message to every other member through
/// a `GroupClient` over a native file store, and prints one line
/// `group-scale members=N snapshot_bytes=... ` for the runner. It asserts what
/// it can count exactly: the commits of one logical send are one for the intent
/// and three per recipient. It is ignored so that `cargo test` does not run a
/// measurement; the runner passes `--ignored`. Nothing here is a budget.
#[tokio::test]
#[ignore = "measurement probe: run by tooling/measure-group-chat.sh"]
async fn group_scale_probe() {
    let only: Option<usize> = std::env::var("GROUP_SCALE_MEMBERS")
        .ok()
        .map(|value| value.parse().expect("GROUP_SCALE_MEMBERS is a number"));
    let (directory, relay) = start_server().await;
    for members in [2usize, 3, 8] {
        if only.is_some_and(|only| only != members) {
            continue;
        }
        let path = std::env::temp_dir().join(format!(
            "group-scale-{members}-{}.snapshot",
            std::process::id()
        ));
        let store = CountingFileStore {
            inner: Arc::new(Mutex::new(crate::operation_store::FileOperationStore::new(
                &path,
            ))),
            commits: Arc::new(Mutex::new(0)),
        };
        let alice_config = config(directory, relay, &format!("+scale{members}a"), 1);
        let mut alice = GroupClient::open(
            DefaultClient::connect(&alice_config).await.unwrap(),
            store.clone(),
        )
        .await
        .unwrap();
        alice.create_group(gid()).unwrap();
        let alice_member = alice.member().unwrap();
        let mut others = Vec::new();
        for index in 1..members {
            let other_store = SharedStore::default();
            let mut other = coordinator(
                directory,
                relay,
                &format!("+scale{members}m{index}"),
                &other_store,
            )
            .await;
            other
                .join_group(genesis_of(&alice_member), alice_member.clone())
                .unwrap();
            others.push(other);
        }
        let routes: Vec<(Member, DeviceAddr)> = others
            .iter()
            .map(|other| (other.member().unwrap(), route(other)))
            .collect();
        let mut everyone = vec![alice_member.clone()];
        everyone.extend(routes.iter().map(|(member, _)| member.clone()));
        let successor = alice.next_roster(everyone).unwrap();
        alice
            .install_roster(successor, &routes, None, 0)
            .await
            .unwrap();
        for other in &mut others {
            assert_eq!(
                sole_roster_disposition(&other.receive(0).await.unwrap()),
                RosterDisposition::Accepted
            );
        }
        assert_eq!(alice.roster().unwrap().members.len(), members);
        assert_eq!(alice_member.identity().len(), 32);
        let roster_bytes = alice.roster().unwrap().encode().unwrap().len();
        let receiver_state_bytes = alice.snapshot.application_state.len();

        // One logical send of 1,000 bytes to every other member.
        let commits_before = *store.commits.lock().unwrap();
        let started = std::time::Instant::now();
        let sent = alice.send_group(&routes, vec![0x41; 1_000]).await.unwrap();
        let logical_send_micros = started.elapsed().as_micros();
        let logical_send_commits = *store.commits.lock().unwrap() - commits_before;
        assert!(
            sent.recipients
                .iter()
                .all(|progress| progress.disposition == RecipientDisposition::RelayAccepted)
        );
        assert_eq!(logical_send_commits, 1 + 3 * (members - 1));
        for other in &mut others {
            assert_eq!(other.receive(0).await.unwrap().events().len(), 1);
        }

        let snapshot_bytes = std::fs::metadata(&path).unwrap().len();
        let provider_state_bytes = alice.snapshot.provider_state.len();
        // The latency of one more commit of the final snapshot.
        let mut commit_micros = Vec::new();
        for _ in 0..5 {
            let mut writer = store.clone();
            let started = std::time::Instant::now();
            assert_eq!(writer.commit(&alice.snapshot), CommitOutcome::Committed);
            commit_micros.push(started.elapsed().as_micros());
        }
        commit_micros.sort_unstable();

        // Restart: read the snapshot back, reconnect from its provider state,
        // and rebuild the group from it.
        drop(alice);
        let started = std::time::Instant::now();
        let mut recovering = store.clone();
        let state = recovered_provider_state(&mut recovering)
            .unwrap()
            .expect("the store holds a snapshot");
        let client = DefaultClient::connect_with_state(&alice_config, &state)
            .await
            .unwrap();
        let mut restarted = GroupClient::open(client, store.clone()).await.unwrap();
        restarted
            .join_group(genesis_of(&alice_member), alice_member.clone())
            .unwrap();
        let restart_recover_micros = started.elapsed().as_micros();
        assert_eq!(restarted.roster().unwrap().members.len(), members);

        println!(
            "group-scale members={members} snapshot_bytes={snapshot_bytes} \
             provider_state_bytes={provider_state_bytes} \
             logical_send_commits={logical_send_commits} \
             logical_send_micros={logical_send_micros} \
             restart_recover_micros={restart_recover_micros} \
             roster_bytes={roster_bytes} receiver_state_bytes={receiver_state_bytes} \
             commit_median_micros={}",
            commit_micros[2]
        );
        crate::operation_store::remove_store_files(&path);
    }
}

/// The steady-state measurement `tooling/measure-group-chat.sh` runs next to the
/// per-size one. `group_scale_probe` measures the first send from an empty
/// outbox; a group in use keeps its live and its sixteen most recent terminal
/// sends in the snapshot (0133), which is larger and slower to rewrite. This
/// probe has the authority of an eight-member group send `GROUP_STEADY_SENDS`
/// (default 17) logical messages of 1,000 bytes in a row through a `GroupClient`
/// over a native file store, with real 32-byte identities, and prints one line
/// per send and a last line, `group-steady members=8 sends=N snapshot_bytes=...`,
/// for the last send. It asserts what it can count: every send costs the same
/// 22 whole-snapshot commits (one for the intent and three per recipient), every
/// recipient's relay copy is accepted, and the outbox retains at most the sixteen
/// most recent terminal sends. It is ignored so that `cargo test` does not run a
/// measurement. The name contains `group_scale_probe` so that the demo script's
/// `--skip group_scale_probe` skips it too. Nothing here is a budget.
#[tokio::test]
#[ignore = "measurement probe: run by tooling/measure-group-chat.sh"]
async fn group_scale_probe_steady_state() {
    const MEMBERS: usize = 8;
    let sends: usize = std::env::var("GROUP_STEADY_SENDS")
        .ok()
        .map_or(17, |value| {
            value.parse().expect("GROUP_STEADY_SENDS is a number")
        });
    let (directory, relay) = start_server().await;
    let path = std::env::temp_dir().join(format!(
        "group-steady-{MEMBERS}-{}.snapshot",
        std::process::id()
    ));
    let store = CountingFileStore {
        inner: Arc::new(Mutex::new(crate::operation_store::FileOperationStore::new(
            &path,
        ))),
        commits: Arc::new(Mutex::new(0)),
    };
    let alice_config = config(directory, relay, "+steadya", 1);
    let mut alice = GroupClient::open(
        DefaultClient::connect(&alice_config).await.unwrap(),
        store.clone(),
    )
    .await
    .unwrap();
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let mut others = Vec::new();
    for index in 1..MEMBERS {
        let other_store = SharedStore::default();
        let mut other =
            coordinator(directory, relay, &format!("+steadym{index}"), &other_store).await;
        other
            .join_group(genesis_of(&alice_member), alice_member.clone())
            .unwrap();
        others.push(other);
    }
    let routes: Vec<(Member, DeviceAddr)> = others
        .iter()
        .map(|other| (other.member().unwrap(), route(other)))
        .collect();
    let mut everyone = vec![alice_member.clone()];
    everyone.extend(routes.iter().map(|(member, _)| member.clone()));
    let successor = alice.next_roster(everyone).unwrap();
    alice
        .install_roster(successor, &routes, None, 0)
        .await
        .unwrap();
    for other in &mut others {
        assert_eq!(
            sole_roster_disposition(&other.receive(0).await.unwrap()),
            RosterDisposition::Accepted
        );
    }
    assert_eq!(alice.roster().unwrap().members.len(), MEMBERS);

    let mut last = (0u128, 0usize, 0u64);
    for index in 1..=sends {
        let commits_before = *store.commits.lock().unwrap();
        let started = std::time::Instant::now();
        let sent = alice.send_group(&routes, vec![0x41; 1_000]).await.unwrap();
        let micros = started.elapsed().as_micros();
        let commits = *store.commits.lock().unwrap() - commits_before;
        assert!(
            sent.recipients
                .iter()
                .all(|progress| progress.disposition == RecipientDisposition::RelayAccepted)
        );
        assert_eq!(commits, 1 + 3 * (MEMBERS - 1), "send {index}");
        for other in &mut others {
            assert_eq!(other.receive(0).await.unwrap().events().len(), 1);
        }
        let bytes = std::fs::metadata(&path).unwrap().len();
        println!("group-steady-send n={index} snapshot_bytes={bytes} logical_send_micros={micros}");
        last = (micros, commits, bytes);
    }
    let terminal = alice
        .group
        .as_ref()
        .unwrap()
        .outbox
        .sends()
        .iter()
        .filter(|send| send.is_terminal())
        .count();
    assert!(terminal <= 16);
    println!(
        "group-steady members={MEMBERS} sends={sends} snapshot_bytes={} \
         logical_send_commits={} logical_send_micros={} terminal_sends_retained={terminal} \
         provider_state_bytes={} outbox_records={} inbox_records={} control_records={}",
        last.2,
        last.1,
        last.0,
        alice.snapshot.provider_state.len(),
        alice.snapshot.outbox.len(),
        alice.snapshot.inbox.len(),
        alice.snapshot.group_controls.len(),
    );
    crate::operation_store::remove_store_files(&path);
}
