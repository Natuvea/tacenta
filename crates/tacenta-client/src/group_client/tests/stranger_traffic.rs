//! What a registered peer that is not in the group can do to the authority's control records with the
//! roster payloads it is allowed to send (decisions 0141, 0145): fill the transcript the coordinator
//! keeps. Every test drives real coordinators against the in-process directory and relay with the
//! real provider; the stranger is a plain client with its own account that knows the group ID and
//! the authority's route.

use super::roster_fanout::{Crew, crew};
use super::*;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A control that names the stranger as its authority: refused `WrongAuthority`, and written to the
/// coordinator's control transcript like every roster payload.
fn stranger_control(mallory: &Member) -> Roster {
    Roster::new(
        gid(),
        9,
        [3; DIGEST_LEN],
        mallory.clone(),
        POLICY_VERSION_V1,
        false,
        vec![mallory.clone()],
    )
    .unwrap()
}

/// The stranger sends `count` roster controls to Alice, who receives them all.
async fn flood_the_authority(crew: &mut Crew, mallory: &mut DefaultClient, count: usize) {
    let alice_route = route(&crew.alice);
    let junk = GroupPayload::Roster(stranger_control(&member_of(mallory)))
        .encode()
        .unwrap();
    for _ in 0..count {
        mallory
            .send_as(&alice_route, &junk, Kind::Group)
            .await
            .unwrap();
    }
    let mut received = 0;
    while received < count {
        let inbound = crew.alice.receive(0).await.unwrap();
        assert!(!inbound.items.is_empty(), "the flood is still at the relay");
        assert!(
            inbound.items.iter().all(|item| matches!(
                item.outcome,
                GroupOutcome::Roster {
                    disposition: RosterDisposition::Rejected(_),
                    ..
                }
            )),
            "{:?}",
            inbound.items
        );
        received += inbound.items.len();
    }
}

/// Whether the control transcript still holds the roster record (`TCGC`) of `roster`.
fn transcript_holds(client: &GroupClient, roster: &Roster) -> bool {
    let preimage = roster.encode().unwrap();
    client
        .snapshot
        .group_controls
        .iter()
        .any(|record| record.starts_with(b"TCGC") && contains(record, &preimage))
}

fn install_shape(install: &Install) -> (usize, usize, usize) {
    (
        install.delivered.len(),
        install.pending.len(),
        install.unprepared.len(),
    )
}

/// The removed member is told wherever it is listed, whatever a stranger has written into the
/// authority's control transcript first (0141, 0145). 28 controls leave the transcript record of the
/// replaced roster in place, 30 crowd it out, and 1,000 replace the whole transcript; the install is
/// the same in every case, its first call reports everyone delivered, a retry agrees, and the removed
/// member learns it is out.
#[tokio::test]
async fn a_stranger_flood_of_roster_controls_cannot_stop_the_removed_member_being_told() {
    let mut failures = Vec::new();
    for flood in [0usize, 28, 30, 1_000] {
        for removed_first in [false, true] {
            let mut crew = crew(3).await;
            let mut mallory = plain(
                crew.alice_config.directory,
                crew.alice_config.relay,
                "+mallory",
            )
            .await;
            let r1 = crew.alice.roster().unwrap().clone();
            flood_the_authority(&mut crew, &mut mallory, flood).await;
            if flood >= 1_000 {
                assert!(
                    !transcript_holds(&crew.alice, &r1),
                    "the flood replaced the transcript record of the replaced roster"
                );
            }
            // Alice removes member 1; members 0 and 2 stay.
            let r2 = crew
                .alice
                .next_roster(vec![
                    crew.alice_member.clone(),
                    crew.member(0),
                    crew.member(2),
                ])
                .unwrap();
            let recipients = if removed_first {
                vec![crew.recipient(1), crew.recipient(0), crew.recipient(2)]
            } else {
                vec![crew.recipient(0), crew.recipient(2), crew.recipient(1)]
            };
            let context = format!("flood {flood}, removed member first {removed_first}");
            let first = crew
                .alice
                .install_roster(r2.clone(), &recipients, None, 0)
                .await
                .map(|install| install_shape(&install));
            let retry = crew
                .alice
                .install_roster(r2, &recipients, None, 0)
                .await
                .map(|install| install_shape(&install));
            let inbound = crew.others[1].0.receive(0).await.unwrap();
            let learned = inbound.items.iter().any(|item| {
                matches!(
                    item.outcome,
                    GroupOutcome::Roster {
                        disposition: RosterDisposition::Accepted,
                        ..
                    }
                )
            });
            if first.as_ref().ok() != Some(&(3, 0, 0))
                || retry.as_ref().ok() != Some(&(3, 0, 0))
                || !learned
            {
                failures.push(format!(
                    "{context}: first call {first:?}, retry {retry:?}, removed member learned {learned}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The replaced roster is durable state, not a lookup in the transcript: an install that froze after
/// the successor was committed, a flood that replaces the transcript, and a restart, and the retry
/// still tells the removed member (0141, 0145).
#[tokio::test]
async fn the_removed_member_is_still_told_after_a_flood_and_a_restart_of_a_half_finished_install() {
    let mut crew = crew(3).await;
    let mut mallory = plain(
        crew.alice_config.directory,
        crew.alice_config.relay,
        "+mallory",
    )
    .await;
    let r1 = crew.alice.roster().unwrap().clone();
    let r2 = crew
        .alice
        .next_roster(vec![
            crew.alice_member.clone(),
            crew.member(0),
            crew.member(2),
        ])
        .unwrap();
    let recipients = [crew.recipient(0), crew.recipient(1), crew.recipient(2)];
    // Bob: the install and his control (1), the reservation (2), the acceptance (3). The removed
    // member's preparation is the fourth commit.
    crew.alice_store.script(
        [
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Failed,
        ],
        false,
    );
    let frozen = crew
        .alice
        .install_roster(r2.clone(), &recipients, None, 0)
        .await;
    assert!(matches!(frozen, Err(GroupError::Frozen)), "{frozen:?}");
    crew.alice.recover().await.unwrap();
    flood_the_authority(&mut crew, &mut mallory, 100).await;
    assert!(
        !transcript_holds(&crew.alice, &r1),
        "the flood replaced the transcript record of the replaced roster"
    );
    let mut alice = restart(&crew.alice_config, &crew.alice_store).await;
    alice.create_group(gid()).unwrap();
    assert_eq!(alice.roster().unwrap().revision, 2);
    let install = alice
        .install_roster(r2, &recipients, None, 0)
        .await
        .unwrap();
    assert_eq!(install_shape(&install), (3, 0, 0), "{install:?}");
    for (member_client, ..) in &mut crew.others {
        member_client.receive(0).await.unwrap();
        assert_eq!(member_client.roster().unwrap().revision, 2);
    }
}

/// A call that names a member the checkpoint does not cover is refused whole, before anything
/// changes, as 0141 says: with the record of the replaced roster gone, a retry that lists the removed
/// member is `Policy` and commits nothing (0145).
#[tokio::test]
async fn an_installed_successor_whose_replaced_roster_is_unknown_refuses_the_call_before_anything_changes()
 {
    let mut crew = crew(3).await;
    let r2 = crew
        .alice
        .next_roster(vec![
            crew.alice_member.clone(),
            crew.member(0),
            crew.member(2),
        ])
        .unwrap();
    crew.alice
        .install_roster(r2.clone(), &[crew.recipient(0), crew.recipient(2)], None, 0)
        .await
        .unwrap();
    // Nothing tells the removed member's route apart now but the replaced roster.
    crew.alice
        .snapshot
        .group_controls
        .retain(|record| !record.starts_with(b"TCGC") && !record.starts_with(b"TCGS"));
    let generation = crew.alice.generation();
    let refused = crew
        .alice
        .install_roster(
            r2,
            &[crew.recipient(0), crew.recipient(2), crew.recipient(1)],
            None,
            0,
        )
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(crew.alice.generation(), generation, "nothing was committed");
}
