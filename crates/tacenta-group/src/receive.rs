//! Bounded receive dispositions before the client ACKs relay delivery.

use crate::{ApplicationContext, DIGEST_LEN, GroupId, Member, Roster};

const DEDUP_WINDOW: u64 = 64;
const FUTURE_REVISIONS: u64 = 2;
const MAX_DEFERRED: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveRefusal {
    Malformed,
    WrongPeer,
    WrongGroup,
    WrongRecipient,
    NotActive,
    OldRevision,
    InvalidRoster,
    FutureOutOfRange,
    SequenceExpired,
    Conflict,
    DeferredFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveDisposition {
    Accepted { event_id: u64 },
    Duplicate { event_id: u64 },
    Deferred,
    Rejected(ReceiveRefusal),
}

/// A formerly deferred context after it was checked against an accepted roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevalidatedReceive {
    pub context: ApplicationContext,
    pub commitment: [u8; DIGEST_LEN],
    pub disposition: ReceiveDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    group_id: GroupId,
    revision: u64,
    sender: Member,
    sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Accepted {
    key: Key,
    commitment: [u8; DIGEST_LEN],
    event_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Deferred {
    context: ApplicationContext,
    commitment: [u8; DIGEST_LEN],
}

/// Product policy state for one locally accepted roster view. The caller
/// commits the returned disposition with its provider state before ACKing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupReceiver {
    roster: Roster,
    roster_digest: [u8; DIGEST_LEN],
    local: Member,
    accepted: Vec<Accepted>,
    deferred: Vec<Deferred>,
    next_event_id: u64,
}

impl GroupReceiver {
    pub fn new(roster: Roster, roster_digest: [u8; DIGEST_LEN], local: Member) -> Self {
        Self {
            roster,
            roster_digest,
            local,
            accepted: Vec::new(),
            deferred: Vec::new(),
            next_event_id: 0,
        }
    }

    /// Applies only the bounded profile's policy. `authenticated_peer` must be
    /// the peer reported by pairwise processing, never a relay routing label.
    pub fn receive(
        &mut self,
        context: &ApplicationContext,
        authenticated_peer: &Member,
        commitment: [u8; DIGEST_LEN],
    ) -> ReceiveDisposition {
        if authenticated_peer != &context.sender {
            return ReceiveDisposition::Rejected(ReceiveRefusal::WrongPeer);
        }
        if context.group_id != self.roster.group_id {
            return ReceiveDisposition::Rejected(ReceiveRefusal::WrongGroup);
        }
        if context.recipient != self.local {
            return ReceiveDisposition::Rejected(ReceiveRefusal::WrongRecipient);
        }
        if !self.is_active(&context.sender) || !self.is_active(&self.local) {
            return ReceiveDisposition::Rejected(ReceiveRefusal::NotActive);
        }

        let key = Key {
            group_id: context.group_id,
            revision: context.revision,
            sender: context.sender.clone(),
            sequence: context.logical_sequence,
        };
        if context.revision < self.roster.revision {
            return ReceiveDisposition::Rejected(ReceiveRefusal::OldRevision);
        }
        if context.revision == self.roster.revision {
            if context.roster_digest != self.roster_digest {
                return ReceiveDisposition::Rejected(ReceiveRefusal::InvalidRoster);
            }
            return self.accept_current(key, commitment);
        }
        if context.revision > self.roster.revision.saturating_add(FUTURE_REVISIONS) {
            return ReceiveDisposition::Rejected(ReceiveRefusal::FutureOutOfRange);
        }
        self.defer(context, commitment)
    }

    /// Installs a roster that the control layer has already authenticated and
    /// accepted, then repeats ordinary receive validation for every deferred
    /// item. Callers must durably record the returned dispositions with the
    /// roster transition before acknowledging or delivering any accepted item.
    pub fn install_accepted_roster(
        &mut self,
        roster: Roster,
        roster_digest: [u8; DIGEST_LEN],
    ) -> Result<Vec<RevalidatedReceive>, ReceiveRefusal> {
        if roster.group_id != self.roster.group_id {
            return Err(ReceiveRefusal::WrongGroup);
        }
        self.roster = roster;
        self.roster_digest = roster_digest;
        let deferred = std::mem::take(&mut self.deferred);
        Ok(deferred
            .into_iter()
            .map(|item| RevalidatedReceive {
                disposition: self.receive(&item.context, &item.context.sender, item.commitment),
                context: item.context,
                commitment: item.commitment,
            })
            .collect())
    }

    fn is_active(&self, member: &Member) -> bool {
        !self.roster.closed && self.roster.members.iter().any(|known| known == member)
    }

    fn accept_current(&mut self, key: Key, commitment: [u8; DIGEST_LEN]) -> ReceiveDisposition {
        if let Some(existing) = self.accepted.iter().find(|item| item.key == key) {
            return if existing.commitment == commitment {
                ReceiveDisposition::Duplicate {
                    event_id: existing.event_id,
                }
            } else {
                ReceiveDisposition::Rejected(ReceiveRefusal::Conflict)
            };
        }
        let newest = self
            .accepted
            .iter()
            .filter(|item| item.key.sender == key.sender && item.key.revision == key.revision)
            .map(|item| item.key.sequence)
            .max();
        if newest.is_some_and(|sequence| key.sequence.saturating_add(DEDUP_WINDOW) <= sequence) {
            return ReceiveDisposition::Rejected(ReceiveRefusal::SequenceExpired);
        }
        let event_id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);
        self.accepted.push(Accepted {
            key,
            commitment,
            event_id,
        });
        ReceiveDisposition::Accepted { event_id }
    }

    fn defer(
        &mut self,
        context: &ApplicationContext,
        commitment: [u8; DIGEST_LEN],
    ) -> ReceiveDisposition {
        let key = Key {
            group_id: context.group_id,
            revision: context.revision,
            sender: context.sender.clone(),
            sequence: context.logical_sequence,
        };
        if let Some(existing) = self.deferred.iter().find(|item| {
            item.context.group_id == key.group_id
                && item.context.revision == key.revision
                && item.context.sender == key.sender
                && item.context.logical_sequence == key.sequence
        }) {
            return if existing.commitment == commitment {
                ReceiveDisposition::Deferred
            } else {
                ReceiveDisposition::Rejected(ReceiveRefusal::Conflict)
            };
        }
        if self.deferred.len() == MAX_DEFERRED {
            return ReceiveDisposition::Rejected(ReceiveRefusal::DeferredFull);
        }
        self.deferred.push(Deferred {
            context: context.clone(),
            commitment,
        });
        ReceiveDisposition::Deferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GroupId, POLICY_VERSION_V1};

    fn alice() -> Member {
        Member::new(b"alice".to_vec(), vec![1])
    }
    fn bob() -> Member {
        Member::new(b"bob".to_vec(), vec![1])
    }
    fn group() -> GroupId {
        GroupId::new(*b"bounded-group-id")
    }
    fn receiver() -> GroupReceiver {
        GroupReceiver::new(
            Roster::new(
                group(),
                2,
                [0; DIGEST_LEN],
                alice(),
                POLICY_VERSION_V1,
                false,
                vec![alice(), bob()],
            )
            .unwrap(),
            [9; DIGEST_LEN],
            bob(),
        )
    }
    fn context(revision: u64, sequence: u64) -> ApplicationContext {
        ApplicationContext::new(
            group(),
            revision,
            [9; DIGEST_LEN],
            alice(),
            bob(),
            sequence,
            b"hello".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn current_messages_deduplicate_with_stable_event_ids() {
        let mut receiver = receiver();
        assert_eq!(
            receiver.receive(&context(2, 7), &alice(), [1; DIGEST_LEN]),
            ReceiveDisposition::Accepted { event_id: 0 }
        );
        assert_eq!(
            receiver.receive(&context(2, 7), &alice(), [1; DIGEST_LEN]),
            ReceiveDisposition::Duplicate { event_id: 0 }
        );
        assert_eq!(
            receiver.receive(&context(2, 7), &alice(), [2; DIGEST_LEN]),
            ReceiveDisposition::Rejected(ReceiveRefusal::Conflict)
        );
    }

    #[test]
    fn peer_roster_and_future_bounds_are_enforced() {
        let mut receiver = receiver();
        assert_eq!(
            receiver.receive(&context(2, 7), &bob(), [1; DIGEST_LEN]),
            ReceiveDisposition::Rejected(ReceiveRefusal::WrongPeer)
        );
        assert_eq!(
            receiver.receive(&context(4, 7), &alice(), [1; DIGEST_LEN]),
            ReceiveDisposition::Deferred
        );
        assert_eq!(
            receiver.receive(&context(5, 7), &alice(), [1; DIGEST_LEN]),
            ReceiveDisposition::Rejected(ReceiveRefusal::FutureOutOfRange)
        );
    }

    #[test]
    fn deferred_items_are_revalidated_before_a_new_roster_can_deliver_them() {
        let mut receiver = receiver();
        let future = ApplicationContext::new(
            group(),
            3,
            [10; DIGEST_LEN],
            alice(),
            bob(),
            7,
            b"hello".to_vec(),
        )
        .unwrap();
        assert_eq!(
            receiver.receive(&future, &alice(), [1; DIGEST_LEN]),
            ReceiveDisposition::Deferred
        );
        let next = Roster::new(
            group(),
            3,
            [9; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap();
        assert_eq!(
            receiver.install_accepted_roster(next, [10; DIGEST_LEN]),
            Ok(vec![RevalidatedReceive {
                context: future,
                commitment: [1; DIGEST_LEN],
                disposition: ReceiveDisposition::Accepted { event_id: 0 },
            }])
        );
    }
}
