//! Roster controls held until their predecessor arrives (0142).
//!
//! The authority sends each roster successor to each member as a separate
//! pairwise message. Nothing orders those messages across recipients, retries or
//! the invitation bootstrap, and a control that reaches a member ahead of its
//! predecessor is answered `MissingPredecessor` by the roster view, terminally,
//! after its ciphertext has been consumed. The coordinator therefore keeps the
//! decrypted control: at most [`MAX_DEFERRED_ROSTERS`] of them, only from the
//! pinned authority, in one checkpoint record (`TCGQ`) that each commit replaces
//! whole, and applies them in order when the view reaches them.

use tacenta_group::{Error as GroupError, GROUP_ID_LEN, GroupId, Member, Roster, RosterView};

/// The most controls held at once.
pub(crate) const MAX_DEFERRED_ROSTERS: usize = 4;
/// How far past the view's next revision a control may be and still be held: a
/// control is held for revisions `view + 2` through `view + 1 + HOLD_AHEAD`.
pub(crate) const HOLD_AHEAD: u64 = 4;

const TAG: &[u8; 4] = b"TCGQ";

/// What holding a control did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hold {
    /// The control was added.
    Held,
    /// This exact control was already held.
    Duplicate,
    /// There is no room, or a different control is held for that revision.
    Refused,
}

/// Roster controls waiting for their predecessor, in ascending revision, one per
/// revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeferredRosters {
    rosters: Vec<Roster>,
}

impl DeferredRosters {
    pub(crate) fn rosters(&self) -> &[Roster] {
        &self.rosters
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.rosters.is_empty()
    }

    /// Holds `roster`. A different control for a revision already held is a fork
    /// by the authority: the first is kept and the second refused.
    pub(crate) fn hold(&mut self, roster: Roster) -> Hold {
        if let Some(existing) = self
            .rosters
            .iter()
            .find(|held| held.revision == roster.revision)
        {
            return if existing == &roster {
                Hold::Duplicate
            } else {
                Hold::Refused
            };
        }
        if self.rosters.len() == MAX_DEFERRED_ROSTERS {
            return Hold::Refused;
        }
        self.rosters.push(roster);
        self.rosters.sort_by_key(|held| held.revision);
        Hold::Held
    }

    /// Drops every control whose revision is at or below `revision`: the view has
    /// passed it.
    pub(crate) fn prune_through(&mut self, revision: u64) {
        self.rosters.retain(|held| held.revision > revision);
    }

    /// Drops the control held for `revision`, if any.
    pub(crate) fn remove(&mut self, revision: u64) {
        self.rosters.retain(|held| held.revision != revision);
    }

    /// The held control that is the successor of `view`, if there is one.
    pub(crate) fn next_for(&self, view: &RosterView) -> Option<&Roster> {
        self.rosters.iter().find(|held| {
            Some(held.revision) == view.roster().revision.checked_add(1)
                && held.predecessor_digest == *view.digest()
        })
    }

    /// The checkpoint record for `group_id`: `TCGQ`, the group ID, a count and
    /// each control's roster preimage, length-prefixed.
    pub(crate) fn encode_record(&self, group_id: GroupId) -> Result<Vec<u8>, GroupError> {
        let mut record = TAG.to_vec();
        record.extend_from_slice(group_id.as_bytes());
        record.push(u8::try_from(self.rosters.len()).map_err(|_| GroupError::Malformed)?);
        for roster in &self.rosters {
            let preimage = roster.encode()?;
            let length = u32::try_from(preimage.len()).map_err(|_| GroupError::Malformed)?;
            record.extend_from_slice(&length.to_be_bytes());
            record.extend_from_slice(&preimage);
        }
        Ok(record)
    }

    /// The inverse of [`encode_record`](Self::encode_record), for the group and
    /// the pinned authority the caller selected. It refuses a record for another
    /// group, more than [`MAX_DEFERRED_ROSTERS`] controls, a control of another
    /// authority or group, revisions that do not strictly ascend, a control that
    /// does not re-encode to the bytes it came from, and trailing bytes.
    pub(crate) fn decode_record(
        record: &[u8],
        group_id: GroupId,
        pinned_authority: &Member,
    ) -> Result<Self, GroupError> {
        let mut input = record
            .strip_prefix(TAG.as_slice())
            .ok_or(GroupError::Malformed)?;
        let (recorded, rest) = input
            .split_at_checked(GROUP_ID_LEN)
            .ok_or(GroupError::Malformed)?;
        if recorded != group_id.as_bytes() {
            return Err(GroupError::Malformed);
        }
        let (count, mut rest) = rest.split_first().ok_or(GroupError::Malformed)?;
        if usize::from(*count) > MAX_DEFERRED_ROSTERS {
            return Err(GroupError::Malformed);
        }
        let mut rosters: Vec<Roster> = Vec::with_capacity(usize::from(*count));
        for _ in 0..*count {
            let (length, tail) = rest.split_at_checked(4).ok_or(GroupError::Malformed)?;
            let length = usize::try_from(u32::from_be_bytes(
                length.try_into().map_err(|_| GroupError::Malformed)?,
            ))
            .map_err(|_| GroupError::Malformed)?;
            let (preimage, tail) = tail.split_at_checked(length).ok_or(GroupError::Malformed)?;
            let roster = Roster::decode(preimage)?;
            if roster.group_id != group_id
                || &roster.authority != pinned_authority
                || rosters
                    .last()
                    .is_some_and(|previous| previous.revision >= roster.revision)
                || roster.encode()? != preimage
            {
                return Err(GroupError::NonCanonical);
            }
            rosters.push(roster);
            rest = tail;
        }
        input = rest;
        if !input.is_empty() {
            return Err(GroupError::Malformed);
        }
        Ok(Self { rosters })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacenta_core::crypto::groups::roster_commitment;
    use tacenta_group::{DIGEST_LEN, POLICY_VERSION_V1};

    /// The commitment the roster view compares a successor's predecessor with.
    fn digest_of(roster: &Roster) -> [u8; DIGEST_LEN] {
        roster_commitment(&roster.encode().expect("a valid roster encodes"))
    }

    fn group() -> GroupId {
        GroupId::new(*b"bounded-group-id")
    }

    fn alice() -> Member {
        Member::new(b"alice".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob".to_vec(), vec![1])
    }

    fn roster(revision: u64, predecessor: [u8; DIGEST_LEN], members: Vec<Member>) -> Roster {
        Roster::new(
            group(),
            revision,
            predecessor,
            alice(),
            POLICY_VERSION_V1,
            false,
            members,
        )
        .unwrap()
    }

    fn chain(length: u64) -> Vec<Roster> {
        let mut rosters = Vec::new();
        let mut predecessor = [7; DIGEST_LEN];
        for revision in 1..=length {
            let members = if revision % 2 == 0 {
                vec![alice()]
            } else {
                vec![alice(), bob()]
            };
            let next = roster(revision, predecessor, members);
            predecessor = digest_of(&next);
            rosters.push(next);
        }
        rosters
    }

    #[test]
    fn the_queue_limits_are_pinned_by_literal() {
        assert_eq!(MAX_DEFERRED_ROSTERS, 4);
        assert_eq!(HOLD_AHEAD, 4);
    }

    #[test]
    fn a_queue_holds_four_controls_one_per_revision_in_order() {
        let rosters = chain(6);
        let mut queue = DeferredRosters::default();
        assert_eq!(queue.hold(rosters[4].clone()), Hold::Held);
        assert_eq!(queue.hold(rosters[2].clone()), Hold::Held);
        assert_eq!(queue.hold(rosters[3].clone()), Hold::Held);
        assert_eq!(queue.hold(rosters[5].clone()), Hold::Held);
        let revisions: Vec<u64> = queue.rosters().iter().map(|held| held.revision).collect();
        assert_eq!(revisions, [3, 4, 5, 6]);
        // Full: a fifth is refused; an exact repeat is a duplicate; a different
        // control for a held revision is refused.
        assert_eq!(queue.hold(rosters[0].clone()), Hold::Refused);
        assert_eq!(queue.hold(rosters[3].clone()), Hold::Duplicate);
        let fork = roster(4, [9; DIGEST_LEN], vec![alice(), bob()]);
        assert_eq!(queue.hold(fork), Hold::Refused);
        assert_eq!(queue.rosters().len(), 4);
    }

    #[test]
    fn pruning_and_removing_drop_only_what_they_name() {
        let rosters = chain(5);
        let mut queue = DeferredRosters::default();
        for roster in &rosters[1..] {
            queue.hold(roster.clone());
        }
        queue.prune_through(3);
        let revisions: Vec<u64> = queue.rosters().iter().map(|held| held.revision).collect();
        assert_eq!(revisions, [4, 5]);
        queue.remove(5);
        let revisions: Vec<u64> = queue.rosters().iter().map(|held| held.revision).collect();
        assert_eq!(revisions, [4]);
        queue.remove(9);
        assert_eq!(queue.rosters().len(), 1);
        queue.prune_through(4);
        assert!(queue.is_empty());
    }

    #[test]
    fn only_the_successor_of_the_view_is_next() {
        let rosters = chain(4);
        let mut queue = DeferredRosters::default();
        queue.hold(rosters[2].clone());
        queue.hold(rosters[3].clone());
        let view = RosterView::accept_source(&alice(), rosters[0].clone(), digest_of(&rosters[0]))
            .unwrap();
        // Revision 3 does not follow revision 1.
        assert_eq!(queue.next_for(&view), None);
        let mut view = view;
        assert_eq!(
            view.accept_successor(&alice(), rosters[1].clone(), digest_of(&rosters[1])),
            tacenta_group::RosterDisposition::Accepted
        );
        assert_eq!(queue.next_for(&view), Some(&rosters[2]));
        // A held control with the right revision and the wrong predecessor is not
        // the successor.
        let mut forked = DeferredRosters::default();
        forked.hold(roster(3, [1; DIGEST_LEN], vec![alice()]));
        assert_eq!(forked.next_for(&view), None);
    }

    #[test]
    fn the_record_round_trips_and_refuses_everything_else() {
        let rosters = chain(5);
        let mut queue = DeferredRosters::default();
        for roster in &rosters[1..] {
            queue.hold(roster.clone());
        }
        let record = queue.encode_record(group()).unwrap();
        assert_eq!(&record[..4], b"TCGQ");
        assert_eq!(
            DeferredRosters::decode_record(&record, group(), &alice()),
            Ok(queue.clone())
        );
        // An empty queue is a record too: it is what replaces a longer one.
        let empty = DeferredRosters::default().encode_record(group()).unwrap();
        assert_eq!(
            DeferredRosters::decode_record(&empty, group(), &alice()),
            Ok(DeferredRosters::default())
        );
        // Another group, another authority, a truncation, trailing bytes and a
        // fifth control are refused.
        let other = GroupId::new(*b"another-group-id");
        assert!(DeferredRosters::decode_record(&record, other, &alice()).is_err());
        assert!(DeferredRosters::decode_record(&record, group(), &bob()).is_err());
        assert!(
            DeferredRosters::decode_record(&record[..record.len() - 1], group(), &alice()).is_err()
        );
        let mut trailing = record.clone();
        trailing.push(0);
        assert!(DeferredRosters::decode_record(&trailing, group(), &alice()).is_err());
        let mut five = record.clone();
        five[4 + GROUP_ID_LEN] = 5;
        assert!(DeferredRosters::decode_record(&five, group(), &alice()).is_err());
    }

    #[test]
    fn revisions_must_strictly_ascend_in_a_record() {
        let rosters = chain(3);
        let mut record = TAG.to_vec();
        record.extend_from_slice(group().as_bytes());
        record.push(2);
        for roster in [&rosters[2], &rosters[1]] {
            let preimage = roster.encode().unwrap();
            record.extend_from_slice(&(preimage.len() as u32).to_be_bytes());
            record.extend_from_slice(&preimage);
        }
        assert_eq!(
            DeferredRosters::decode_record(&record, group(), &alice()),
            Err(GroupError::NonCanonical)
        );
    }
}
