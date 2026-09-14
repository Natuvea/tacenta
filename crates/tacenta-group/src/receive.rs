//! Bounded receive dispositions before the client ACKs relay delivery.

use crate::{ApplicationContext, DIGEST_LEN, GroupId, Member, Roster};

const DEDUP_WINDOW: u64 = 64;
const FUTURE_REVISIONS: u64 = 2;
const MAX_DEFERRED: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveRefusal {
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
    key: Key,
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
        self.defer(key, commitment)
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

    fn defer(&mut self, key: Key, commitment: [u8; DIGEST_LEN]) -> ReceiveDisposition {
        if let Some(existing) = self.deferred.iter().find(|item| item.key == key) {
            return if existing.commitment == commitment {
                ReceiveDisposition::Deferred
            } else {
                ReceiveDisposition::Rejected(ReceiveRefusal::Conflict)
            };
        }
        if self.deferred.len() == MAX_DEFERRED {
            return ReceiveDisposition::Rejected(ReceiveRefusal::DeferredFull);
        }
        self.deferred.push(Deferred { key, commitment });
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
}
