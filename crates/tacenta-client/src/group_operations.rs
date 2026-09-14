//! The client-side bridge between bounded group policy and the core helper.
//!
//! It does not perform pairwise encryption or transport. Its caller supplies
//! the ciphertext produced for the canonical application context, and this
//! module records the standalone core's commitment of that exact context with
//! the immutable recipient record before the durable coordinator can hand it
//! off.

use tacenta_core::crypto::{CryptoStateEffect, groups::payload_commitment};
use tacenta_group::{
    ApplicationContext, Error as GroupError, GroupReceiver, LogicalSend, Member,
    ReceiveDisposition, ReceiveRefusal, RecipientProgress,
};

use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};

/// A group preparation cannot cross its durable boundary.  The caller freezes
/// the affected operation and recovers its snapshot before it tries again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupOperationError {
    Policy,
    Frozen,
}

pub(crate) fn bind_prepared_ciphertext(
    logical_send: &mut LogicalSend,
    recipient: &Member,
    ciphertext: Vec<u8>,
) -> Result<RecipientProgress, GroupError> {
    let context = logical_send.application_context(recipient)?.encode()?;
    let commitment = payload_commitment(&context);
    logical_send
        .record_prepared(recipient, commitment, ciphertext)
        .cloned()
}

/// Records a prepared ciphertext and its core-bound application context in the
/// combined operation snapshot. The logical record changes only after the
/// store reports `Committed`; no transport caller receives ciphertext from a
/// failed or uncertain publication.
pub(crate) fn commit_prepared_ciphertext<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    logical_send: &mut LogicalSend,
    recipient: &Member,
    ciphertext: Vec<u8>,
) -> Result<RecipientProgress, GroupOperationError> {
    let mut candidate_send = logical_send.clone();
    let progress = bind_prepared_ciphertext(&mut candidate_send, recipient, ciphertext)
        .map_err(|_| GroupOperationError::Policy)?;
    let context = candidate_send
        .application_context(recipient)
        .map_err(|_| GroupOperationError::Policy)?
        .encode()
        .map_err(|_| GroupOperationError::Policy)?;
    let commitment = progress
        .context_commitment
        .ok_or(GroupOperationError::Policy)?;
    let ciphertext = progress
        .ciphertext
        .as_deref()
        .ok_or(GroupOperationError::Policy)?;

    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    candidate_snapshot
        .outbox
        .push(encode_prepared_record(&context, &commitment, ciphertext)?);

    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *logical_send = candidate_send;
    Ok(progress)
}

/// Records an authenticated group's disposition with the provider transition
/// that produced it. A caller receives no disposition for acknowledgement or
/// application delivery until the combined candidate snapshot is committed.
pub(crate) fn commit_receive_disposition<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    receiver: &mut GroupReceiver,
    context: &ApplicationContext,
    authenticated_peer: &Member,
    provider_state: Vec<u8>,
    provider_effect: CryptoStateEffect,
) -> Result<ReceiveDisposition, GroupOperationError> {
    let context_bytes = context.encode().map_err(|_| GroupOperationError::Policy)?;
    let commitment = payload_commitment(&context_bytes);
    let mut candidate_receiver = receiver.clone();
    let disposition = candidate_receiver.receive(context, authenticated_peer, commitment);

    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    candidate_snapshot.provider_state = provider_state;
    candidate_snapshot.inbox.push(encode_receive_record(
        provider_effect,
        &context_bytes,
        &commitment,
        disposition,
    )?);
    candidate_snapshot.dedup.push(context_bytes);

    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *receiver = candidate_receiver;
    Ok(disposition)
}

fn encode_prepared_record(
    context: &[u8],
    commitment: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, GroupOperationError> {
    fn put_lp(out: &mut Vec<u8>, value: &[u8]) -> Result<(), GroupOperationError> {
        let length = u32::try_from(value.len()).map_err(|_| GroupOperationError::Policy)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value);
        Ok(())
    }

    let mut record = Vec::new();
    record.extend_from_slice(b"TCGP");
    put_lp(&mut record, context)?;
    record.extend_from_slice(commitment);
    put_lp(&mut record, ciphertext)?;
    Ok(record)
}

fn encode_receive_record(
    provider_effect: CryptoStateEffect,
    context: &[u8],
    commitment: &[u8; 32],
    disposition: ReceiveDisposition,
) -> Result<Vec<u8>, GroupOperationError> {
    fn put_lp(out: &mut Vec<u8>, value: &[u8]) -> Result<(), GroupOperationError> {
        let length = u32::try_from(value.len()).map_err(|_| GroupOperationError::Policy)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value);
        Ok(())
    }
    fn effect_code(effect: CryptoStateEffect) -> u8 {
        match effect {
            CryptoStateEffect::Unchanged => 0,
            CryptoStateEffect::Advanced => 1,
            CryptoStateEffect::Terminal => 2,
        }
    }
    fn refusal_code(refusal: ReceiveRefusal) -> u8 {
        match refusal {
            ReceiveRefusal::WrongPeer => 0,
            ReceiveRefusal::WrongGroup => 1,
            ReceiveRefusal::WrongRecipient => 2,
            ReceiveRefusal::NotActive => 3,
            ReceiveRefusal::OldRevision => 4,
            ReceiveRefusal::InvalidRoster => 5,
            ReceiveRefusal::FutureOutOfRange => 6,
            ReceiveRefusal::SequenceExpired => 7,
            ReceiveRefusal::Conflict => 8,
            ReceiveRefusal::DeferredFull => 9,
        }
    }

    let mut record = Vec::new();
    record.extend_from_slice(b"TCGR");
    record.push(effect_code(provider_effect));
    put_lp(&mut record, context)?;
    record.extend_from_slice(commitment);
    match disposition {
        ReceiveDisposition::Accepted { event_id } => {
            record.push(0);
            record.extend_from_slice(&event_id.to_be_bytes());
        }
        ReceiveDisposition::Duplicate { event_id } => {
            record.push(1);
            record.extend_from_slice(&event_id.to_be_bytes());
        }
        ReceiveDisposition::Deferred => record.push(2),
        ReceiveDisposition::Rejected(refusal) => {
            record.push(3);
            record.push(refusal_code(refusal));
        }
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::{
        GroupOperationError, bind_prepared_ciphertext, commit_prepared_ciphertext,
        commit_receive_disposition,
    };
    use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};
    use tacenta_core::crypto::CryptoStateEffect;
    use tacenta_group::{
        ApplicationContext, DIGEST_LEN, GroupId, GroupReceiver, LogicalSend, Member,
        POLICY_VERSION_V1, ReceiveDisposition, ReceiveRefusal, Roster,
    };

    fn alice() -> Member {
        Member::new(b"alice-key".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob-key".to_vec(), vec![1])
    }

    fn logical_send() -> LogicalSend {
        let group_id = GroupId::new(*b"bounded-group-id");
        let roster = Roster::new(
            group_id,
            1,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap();
        LogicalSend::new(
            &roster,
            [5; DIGEST_LEN],
            alice(),
            7,
            vec![bob()],
            b"hello".to_vec(),
        )
        .unwrap()
    }

    fn receiver() -> GroupReceiver {
        let roster = Roster::new(
            GroupId::new(*b"bounded-group-id"),
            1,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap();
        GroupReceiver::new(roster, [8; DIGEST_LEN], bob())
    }

    fn receive_context() -> ApplicationContext {
        ApplicationContext::new(
            GroupId::new(*b"bounded-group-id"),
            1,
            [8; DIGEST_LEN],
            alice(),
            bob(),
            3,
            b"hello".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn prepared_ciphertext_carries_the_cores_exact_context_commitment() {
        let mut send = logical_send();
        let progress = bind_prepared_ciphertext(&mut send, &bob(), vec![1, 2, 3]).unwrap();
        let context = send.application_context(&bob()).unwrap().encode().unwrap();
        assert_eq!(
            progress.context_commitment,
            Some(tacenta_core::crypto::groups::payload_commitment(&context))
        );
        assert_eq!(progress.ciphertext, Some(vec![1, 2, 3]));
    }

    struct Store {
        outcome: CommitOutcome,
        committed: Option<OperationSnapshot>,
    }

    impl OperationStore for Store {
        fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
            if self.outcome == CommitOutcome::Committed {
                self.committed = Some(snapshot.clone());
            }
            self.outcome
        }

        fn recover(&mut self) -> Result<Option<OperationSnapshot>, ()> {
            Ok(self.committed.clone())
        }
    }

    #[test]
    fn durable_preparation_publishes_context_and_ciphertext_together() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut send = logical_send();
        let progress =
            commit_prepared_ciphertext(&mut store, &mut snapshot, &mut send, &bob(), vec![1, 2, 3])
                .unwrap();

        assert_eq!(snapshot.generation, 5);
        assert_eq!(store.recover().unwrap(), Some(snapshot.clone()));
        assert_eq!(progress.ciphertext, Some(vec![1, 2, 3]));
        assert_eq!(snapshot.outbox.len(), 1);
        assert_eq!(&snapshot.outbox[0][..4], b"TCGP");
    }

    #[test]
    fn uncertain_publication_freezes_without_mutating_the_live_group_record() {
        let mut store = Store {
            outcome: CommitOutcome::Unknown,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let before_snapshot = snapshot.clone();
        let mut send = logical_send();
        let before_send = send.clone();

        assert_eq!(
            commit_prepared_ciphertext(&mut store, &mut snapshot, &mut send, &bob(), vec![1]),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(snapshot, before_snapshot);
        assert_eq!(send, before_send);
        assert_eq!(store.recover().unwrap(), None);
    }

    #[test]
    fn receive_disposition_commits_before_it_can_be_returned_for_delivery() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(9);
        let mut receiver = receiver();

        assert_eq!(
            commit_receive_disposition(
                &mut store,
                &mut snapshot,
                &mut receiver,
                &receive_context(),
                &alice(),
                vec![4, 5, 6],
                CryptoStateEffect::Advanced,
            ),
            Ok(ReceiveDisposition::Accepted { event_id: 0 })
        );
        assert_eq!(snapshot.generation, 10);
        assert_eq!(snapshot.provider_state, vec![4, 5, 6]);
        assert_eq!(snapshot.inbox.len(), 1);
        assert_eq!(&snapshot.inbox[0][..5], b"TCGR\x01");
        assert_eq!(snapshot.dedup, vec![receive_context().encode().unwrap()]);
        assert_eq!(store.recover().unwrap(), Some(snapshot));
    }

    #[test]
    fn terminal_group_rejection_retains_the_provider_transition() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(2);
        let mut receiver = receiver();

        assert_eq!(
            commit_receive_disposition(
                &mut store,
                &mut snapshot,
                &mut receiver,
                &receive_context(),
                &bob(),
                vec![9],
                CryptoStateEffect::Terminal,
            ),
            Ok(ReceiveDisposition::Rejected(ReceiveRefusal::WrongPeer))
        );
        assert_eq!(snapshot.provider_state, vec![9]);
        assert_eq!(&snapshot.inbox[0][..5], b"TCGR\x02");
        assert_eq!(store.recover().unwrap(), Some(snapshot));
    }

    #[test]
    fn unknown_receive_publication_freezes_without_returning_a_disposition() {
        let mut store = Store {
            outcome: CommitOutcome::Unknown,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(2);
        let before_snapshot = snapshot.clone();
        let mut receiver = receiver();
        let before_receiver = receiver.clone();

        assert_eq!(
            commit_receive_disposition(
                &mut store,
                &mut snapshot,
                &mut receiver,
                &receive_context(),
                &alice(),
                vec![9],
                CryptoStateEffect::Advanced,
            ),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(snapshot, before_snapshot);
        assert_eq!(receiver, before_receiver);
        assert_eq!(store.recover().unwrap(), None);
    }
}
