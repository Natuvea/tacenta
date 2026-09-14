//! Immutable logical fan-out records for the bounded group experiment.

use crate::{
    ApplicationContext, DIGEST_LEN, Error, GroupId, MAX_LIVE_LOGICAL_SENDS, MAX_PAYLOAD_LEN,
    Member, RESERVED_REVISION, Roster,
};
use std::collections::BTreeSet;

/// An application identifier allocated independently from pairwise ratchets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalMessageId {
    pub group_id: GroupId,
    pub revision: u64,
    pub sender: Member,
    pub sequence: u64,
}

impl LogicalMessageId {
    pub fn new(
        group_id: GroupId,
        revision: u64,
        sender: Member,
        sequence: u64,
    ) -> Result<Self, Error> {
        if revision == RESERVED_REVISION {
            return Err(Error::ReservedRevision);
        }
        Ok(Self {
            group_id,
            revision,
            sender,
            sequence,
        })
    }
}

/// The externally meaningful state for one recipient's immutable ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientDisposition {
    Pending,
    Prepared,
    HandedOff,
    RelayAccepted,
    Cancelled,
    CancelledAfterHandoff,
    ExhaustedUnknown,
}

/// The durable value an operation coordinator carries for one recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientProgress {
    pub recipient: Member,
    pub disposition: RecipientDisposition,
    /// The core-derived commitment of this recipient's canonical application
    /// context. It is retained with ciphertext and cannot change on retry.
    pub context_commitment: Option<[u8; DIGEST_LEN]>,
    pub ciphertext: Option<Vec<u8>>,
    pub attempts_reserved: u8,
}

/// A fixed-recipient application send.  This structure makes no transport or
/// delivery claim; its owner must persist it before passing a ciphertext to
/// the provider or transport coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalSend {
    pub id: LogicalMessageId,
    pub roster_digest: [u8; DIGEST_LEN],
    pub payload: Vec<u8>,
    recipients: Vec<RecipientProgress>,
}

/// Bounded durable ownership of a group's logical send records. The client
/// serializes this value with its snapshot before allowing any preparation or
/// handoff to cross an external boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupOutbox {
    group_id: GroupId,
    sends: Vec<LogicalSend>,
}

impl GroupOutbox {
    pub fn new(group_id: GroupId) -> Self {
        Self {
            group_id,
            sends: Vec::new(),
        }
    }

    pub fn sends(&self) -> &[LogicalSend] {
        &self.sends
    }

    /// Adds a distinct live logical send. An exact replay uses the prior
    /// immutable record, while changed data for its ID cannot replace it.
    pub fn record(&mut self, send: LogicalSend) -> Result<&LogicalSend, Error> {
        if send.id.group_id != self.group_id {
            return Err(Error::Conflict);
        }
        if let Some(position) = self.sends.iter().position(|known| known.id == send.id) {
            if self.sends[position].same_immutable_fields(&send) {
                return Ok(&self.sends[position]);
            }
            return Err(Error::Conflict);
        }
        if self.sends.iter().filter(|send| !send.is_terminal()).count() >= MAX_LIVE_LOGICAL_SENDS {
            return Err(Error::OutboxFull);
        }
        self.sends.push(send);
        Ok(self.sends.last().expect("just inserted"))
    }

    /// Applies a locally accepted newer roster to all its logical records.
    pub fn cancel_for_newer_roster(&mut self, revision: u64) {
        for send in &mut self.sends {
            send.cancel_for_newer_roster(revision);
        }
    }
}

impl LogicalSend {
    /// Allocates the immutable group, revision, sender, payload, and recipient
    /// set before any per-recipient pairwise preparation occurs.
    pub fn new(
        roster: &Roster,
        roster_digest: [u8; DIGEST_LEN],
        sender: Member,
        sequence: u64,
        recipients: Vec<Member>,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        if roster.closed {
            return Err(Error::Closed);
        }
        if roster.revision == RESERVED_REVISION {
            return Err(Error::ReservedRevision);
        }
        if !roster.members.iter().any(|member| member == &sender) {
            return Err(Error::NotMember);
        }
        if recipients.is_empty() {
            return Err(Error::EmptyRecipients);
        }
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        validate_recipients(roster, &recipients)?;
        Ok(Self {
            id: LogicalMessageId::new(roster.group_id, roster.revision, sender, sequence)?,
            roster_digest,
            payload,
            recipients: recipients
                .into_iter()
                .map(|recipient| RecipientProgress {
                    recipient,
                    disposition: RecipientDisposition::Pending,
                    context_commitment: None,
                    ciphertext: None,
                    attempts_reserved: 0,
                })
                .collect(),
        })
    }

    pub fn recipients(&self) -> &[RecipientProgress] {
        &self.recipients
    }

    pub fn is_terminal(&self) -> bool {
        self.recipients.iter().all(|progress| {
            matches!(
                progress.disposition,
                RecipientDisposition::RelayAccepted
                    | RecipientDisposition::Cancelled
                    | RecipientDisposition::CancelledAfterHandoff
                    | RecipientDisposition::ExhaustedUnknown
            )
        })
    }

    fn same_immutable_fields(&self, candidate: &Self) -> bool {
        self.id == candidate.id
            && self.roster_digest == candidate.roster_digest
            && self.payload == candidate.payload
            && self.recipients.len() == candidate.recipients.len()
            && self
                .recipients
                .iter()
                .zip(&candidate.recipients)
                .all(|(left, right)| left.recipient == right.recipient)
    }

    /// Produces the exact canonical plaintext that must be encrypted for this
    /// recipient.  Pairwise encryption and persistence happen outside this
    /// crate; the result is immutable under this logical identifier.
    pub fn application_context(&self, recipient: &Member) -> Result<ApplicationContext, Error> {
        self.progress(recipient)?;
        ApplicationContext::new(
            self.id.group_id,
            self.id.revision,
            self.roster_digest,
            self.id.sender.clone(),
            recipient.clone(),
            self.id.sequence,
            self.payload.clone(),
        )
    }

    /// Stores a recipient's ciphertext exactly once.  An equal retry is safe;
    /// a changed ciphertext conflicts instead of silently replacing ratchet
    /// output.
    pub fn record_prepared(
        &mut self,
        recipient: &Member,
        context_commitment: [u8; DIGEST_LEN],
        ciphertext: Vec<u8>,
    ) -> Result<&RecipientProgress, Error> {
        let progress = self.progress_mut(recipient)?;
        match progress.disposition {
            RecipientDisposition::Pending => {
                progress.context_commitment = Some(context_commitment);
                progress.ciphertext = Some(ciphertext);
                progress.disposition = RecipientDisposition::Prepared;
                Ok(progress)
            }
            RecipientDisposition::Prepared | RecipientDisposition::HandedOff => {
                if progress.context_commitment == Some(context_commitment)
                    && progress.ciphertext.as_deref() == Some(ciphertext.as_slice())
                {
                    Ok(progress)
                } else {
                    Err(Error::Conflict)
                }
            }
            RecipientDisposition::RelayAccepted
            | RecipientDisposition::Cancelled
            | RecipientDisposition::CancelledAfterHandoff
            | RecipientDisposition::ExhaustedUnknown => Err(Error::WrongDisposition),
        }
    }

    /// Reserves an attempt and records a transport handoff of the stored
    /// ciphertext.  The durable coordinator must commit this state before it
    /// performs the actual handoff; a later retry only receives these bytes.
    pub fn reserve_handoff(&mut self, recipient: &Member) -> Result<&RecipientProgress, Error> {
        let progress = self.progress_mut(recipient)?;
        match progress.disposition {
            RecipientDisposition::Prepared | RecipientDisposition::HandedOff => {}
            RecipientDisposition::Pending => return Err(Error::WrongDisposition),
            RecipientDisposition::RelayAccepted
            | RecipientDisposition::Cancelled
            | RecipientDisposition::CancelledAfterHandoff => {
                return Err(Error::WrongDisposition);
            }
            RecipientDisposition::ExhaustedUnknown => return Err(Error::RetryExhausted),
        }
        if progress.ciphertext.is_none() {
            return Err(Error::WrongDisposition);
        }
        if progress.attempts_reserved >= 3 {
            progress.disposition = RecipientDisposition::ExhaustedUnknown;
            return Err(Error::RetryExhausted);
        }
        progress.attempts_reserved += 1;
        progress.disposition = if progress.attempts_reserved == 3 {
            RecipientDisposition::ExhaustedUnknown
        } else {
            RecipientDisposition::HandedOff
        };
        Ok(progress)
    }

    /// Relay acceptance ends automatic retries but is not an application
    /// receipt.
    pub fn record_relay_accepted(
        &mut self,
        recipient: &Member,
    ) -> Result<&RecipientProgress, Error> {
        let progress = self.progress_mut(recipient)?;
        match progress.disposition {
            RecipientDisposition::Prepared | RecipientDisposition::HandedOff => {
                progress.disposition = RecipientDisposition::RelayAccepted;
                Ok(progress)
            }
            RecipientDisposition::Pending
            | RecipientDisposition::Cancelled
            | RecipientDisposition::CancelledAfterHandoff
            | RecipientDisposition::ExhaustedUnknown
            | RecipientDisposition::RelayAccepted => Err(Error::WrongDisposition),
        }
    }

    /// Cancels a recipient after its application context becomes obsolete.
    /// Handoff evidence remains, but a newer roster blocks another automatic
    /// retry of an old context.
    pub fn cancel_for_roster_change(
        &mut self,
        removed: &Member,
    ) -> Result<&RecipientProgress, Error> {
        let progress = self.progress_mut(removed)?;
        match progress.disposition {
            RecipientDisposition::Pending | RecipientDisposition::Prepared => {
                progress.disposition = RecipientDisposition::Cancelled;
            }
            RecipientDisposition::HandedOff => {
                progress.disposition = RecipientDisposition::CancelledAfterHandoff;
            }
            RecipientDisposition::RelayAccepted
            | RecipientDisposition::Cancelled
            | RecipientDisposition::CancelledAfterHandoff
            | RecipientDisposition::ExhaustedUnknown => {}
        }
        Ok(progress)
    }

    /// Stops all incomplete recipients after a locally accepted newer revision.
    pub fn cancel_for_newer_roster(&mut self, revision: u64) {
        if self.id.revision >= revision {
            return;
        }
        for progress in &mut self.recipients {
            match progress.disposition {
                RecipientDisposition::Pending | RecipientDisposition::Prepared => {
                    progress.disposition = RecipientDisposition::Cancelled;
                }
                RecipientDisposition::HandedOff => {
                    progress.disposition = RecipientDisposition::CancelledAfterHandoff;
                }
                RecipientDisposition::RelayAccepted
                | RecipientDisposition::Cancelled
                | RecipientDisposition::CancelledAfterHandoff
                | RecipientDisposition::ExhaustedUnknown => {}
            }
        }
    }

    fn progress(&self, recipient: &Member) -> Result<&RecipientProgress, Error> {
        self.recipients
            .iter()
            .find(|progress| &progress.recipient == recipient)
            .ok_or(Error::NotMember)
    }

    fn progress_mut(&mut self, recipient: &Member) -> Result<&mut RecipientProgress, Error> {
        self.recipients
            .iter_mut()
            .find(|progress| &progress.recipient == recipient)
            .ok_or(Error::NotMember)
    }
}

fn validate_recipients(roster: &Roster, recipients: &[Member]) -> Result<(), Error> {
    let mut previous: Option<&Member> = None;
    let mut identities = BTreeSet::new();
    for recipient in recipients {
        if !roster.members.iter().any(|member| member == recipient) {
            return Err(Error::NotMember);
        }
        if let Some(previous) = previous
            && previous.canonical_sort_key() >= recipient.canonical_sort_key()
        {
            return Err(Error::NonCanonical);
        }
        if !identities.insert(recipient.identity()) {
            return Err(Error::NonCanonical);
        }
        previous = Some(recipient);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Member, POLICY_VERSION_V1};

    fn group() -> GroupId {
        GroupId::new(*b"bounded-group-id")
    }

    fn alice() -> Member {
        Member::new(b"alice-key".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob-key".to_vec(), vec![1])
    }

    fn carol() -> Member {
        Member::new(b"carol-key".to_vec(), vec![1])
    }

    fn roster() -> Roster {
        Roster::new(
            group(),
            2,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob(), carol()],
        )
        .unwrap()
    }

    fn send() -> LogicalSend {
        LogicalSend::new(
            &roster(),
            [9; DIGEST_LEN],
            alice(),
            8,
            vec![bob(), carol()],
            b"hello".to_vec(),
        )
        .unwrap()
    }

    fn send_at(sequence: u64) -> LogicalSend {
        let mut send = send();
        send.id.sequence = sequence;
        send
    }

    #[test]
    fn a_logical_send_fixes_the_context_and_recipient_set() {
        let logical_send = send();
        assert_eq!(logical_send.id.group_id, group());
        assert_eq!(logical_send.id.revision, 2);
        assert_eq!(logical_send.id.sequence, 8);
        assert_eq!(
            logical_send.application_context(&bob()).unwrap().payload,
            b"hello"
        );
        assert_eq!(
            logical_send.application_context(&Member::new(b"eve".to_vec(), vec![1])),
            Err(Error::NotMember)
        );
    }

    #[test]
    fn preparation_and_retry_keep_the_exact_ciphertext() {
        let mut logical_send = send();
        logical_send
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
            .unwrap();
        assert_eq!(
            logical_send
                .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
                .unwrap()
                .ciphertext,
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            logical_send.record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 4]),
            Err(Error::Conflict)
        );
        assert_eq!(
            logical_send.record_prepared(&bob(), [2; DIGEST_LEN], vec![1, 2, 3]),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn attempts_are_bounded_and_exhaustion_never_claims_nondelivery() {
        let mut logical_send = send();
        logical_send
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
            .unwrap();
        for expected_attempt in 1..=3 {
            let progress = logical_send.reserve_handoff(&bob()).unwrap();
            assert_eq!(progress.attempts_reserved, expected_attempt);
        }
        assert_eq!(
            logical_send.recipients()[0].disposition,
            RecipientDisposition::ExhaustedUnknown
        );
        assert_eq!(
            logical_send.reserve_handoff(&bob()),
            Err(Error::RetryExhausted)
        );
    }

    #[test]
    fn roster_change_cancels_old_unsent_work_and_blocks_handoff_retries() {
        let mut logical_send = send();
        logical_send
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1])
            .unwrap();
        logical_send
            .record_prepared(&carol(), [2; DIGEST_LEN], vec![2])
            .unwrap();
        logical_send.reserve_handoff(&bob()).unwrap();
        assert_eq!(
            logical_send
                .cancel_for_roster_change(&bob())
                .unwrap()
                .disposition,
            RecipientDisposition::CancelledAfterHandoff
        );
        assert_eq!(
            logical_send.reserve_handoff(&bob()),
            Err(Error::WrongDisposition)
        );
        assert_eq!(
            logical_send
                .cancel_for_roster_change(&carol())
                .unwrap()
                .disposition,
            RecipientDisposition::Cancelled
        );
    }

    #[test]
    fn newer_roster_cancels_every_incomplete_old_revision_recipient() {
        let mut logical_send = send();
        logical_send
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1])
            .unwrap();
        logical_send.reserve_handoff(&bob()).unwrap();
        logical_send.cancel_for_newer_roster(3);
        assert_eq!(
            logical_send.recipients()[0].disposition,
            RecipientDisposition::CancelledAfterHandoff
        );
        assert_eq!(
            logical_send.recipients()[1].disposition,
            RecipientDisposition::Cancelled
        );
    }

    #[test]
    fn outbox_applies_live_backpressure_without_discarding_terminal_evidence() {
        let mut outbox = GroupOutbox::new(group());
        for sequence in 0..MAX_LIVE_LOGICAL_SENDS as u64 {
            outbox.record(send_at(sequence)).unwrap();
        }
        assert_eq!(outbox.record(send_at(8)), Err(Error::OutboxFull));

        outbox.cancel_for_newer_roster(3);
        for sequence in 8..=15 {
            outbox.record(send_at(sequence)).unwrap();
        }
        assert_eq!(outbox.sends().len(), 16);
        assert_eq!(outbox.record(send_at(16)), Err(Error::OutboxFull));
    }

    #[test]
    fn outbox_retry_uses_the_committed_record_after_recipient_progresses() {
        let mut outbox = GroupOutbox::new(group());
        let original = send_at(4);
        outbox.record(original.clone()).unwrap();
        outbox.sends[0]
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
            .unwrap();

        let recovered = outbox.record(original).unwrap();
        assert_eq!(
            recovered.recipients()[0].disposition,
            RecipientDisposition::Prepared
        );
        assert_eq!(recovered.recipients()[0].ciphertext, Some(vec![1, 2, 3]));
    }

    #[test]
    fn recipients_must_be_active_and_canonical() {
        assert_eq!(
            LogicalSend::new(
                &roster(),
                [9; DIGEST_LEN],
                alice(),
                8,
                vec![carol(), bob()],
                b"hello".to_vec(),
            ),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            LogicalSend::new(
                &roster(),
                [9; DIGEST_LEN],
                alice(),
                8,
                vec![Member::new(b"eve".to_vec(), vec![1])],
                b"hello".to_vec(),
            ),
            Err(Error::NotMember)
        );
    }
}
