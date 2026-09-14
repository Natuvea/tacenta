//! Immutable logical fan-out records for the bounded group experiment.

use crate::{
    ApplicationContext, DIGEST_LEN, Error, GroupId, MAX_LIVE_LOGICAL_SENDS, MAX_MEMBERS,
    MAX_PAYLOAD_LEN, Member, RESERVED_REVISION, Roster,
};
use std::collections::BTreeSet;

const LOGICAL_SEND_DOMAIN: &[u8] = b"Tacenta Group Logical Send v1";

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

/// Whether recording a logical intent inserted a new durable value or reused
/// the prior immutable value for the same logical ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxDisposition {
    Inserted,
    Duplicate,
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

    pub fn send(&self, id: &LogicalMessageId) -> Result<&LogicalSend, Error> {
        self.sends
            .iter()
            .find(|send| &send.id == id)
            .ok_or(Error::Malformed)
    }

    pub fn send_mut(&mut self, id: &LogicalMessageId) -> Result<&mut LogicalSend, Error> {
        self.sends
            .iter_mut()
            .find(|send| &send.id == id)
            .ok_or(Error::Malformed)
    }

    /// Adds a distinct live logical send. An exact replay uses the prior
    /// immutable record, while changed data for its ID cannot replace it.
    pub fn record(&mut self, send: LogicalSend) -> Result<OutboxDisposition, Error> {
        if send.id.group_id != self.group_id {
            return Err(Error::Conflict);
        }
        if let Some(position) = self.sends.iter().position(|known| known.id == send.id) {
            if self.sends[position].same_immutable_fields(&send) {
                return Ok(OutboxDisposition::Duplicate);
            }
            return Err(Error::Conflict);
        }
        if self.sends.iter().filter(|send| !send.is_terminal()).count() >= MAX_LIVE_LOGICAL_SENDS {
            return Err(Error::OutboxFull);
        }
        self.sends.push(send);
        Ok(OutboxDisposition::Inserted)
    }

    /// Applies a locally accepted newer roster to all its logical records.
    pub fn cancel_for_newer_roster(&mut self, revision: u64) {
        for send in &mut self.sends {
            send.cancel_for_newer_roster(revision);
        }
    }

    /// Rebuilds one group's live outbox from the ordered records in a combined
    /// operation snapshot. The caller supplies the core's domain-separated
    /// payload commitment so this policy crate stays crypto-independent.
    pub fn recover_from_transcript(
        group_id: GroupId,
        entries: &[Vec<u8>],
        payload_commitment: impl Fn(&[u8]) -> [u8; DIGEST_LEN],
    ) -> Result<Self, Error> {
        let mut outbox = Self::new(group_id);
        for entry in entries {
            let Some(tag) = entry.get(..4) else {
                if entry.starts_with(b"TCG") {
                    return Err(Error::Malformed);
                }
                continue;
            };
            match tag {
                b"TCGI" => {
                    let send = decode_intent_record(&entry[4..])?;
                    if send.id.group_id != group_id {
                        continue;
                    }
                    if outbox.record(send)? != OutboxDisposition::Inserted {
                        return Err(Error::Conflict);
                    }
                }
                b"TCGP" => {
                    let record = decode_progress_record(&entry[4..])?;
                    if !record.rest.is_empty() {
                        return Err(Error::Malformed);
                    }
                    apply_recovered_preparation(
                        &mut outbox,
                        group_id,
                        &record.context,
                        record.commitment,
                        record.ciphertext,
                        &payload_commitment,
                    )?;
                }
                b"TCGH" => {
                    let record = decode_progress_record(&entry[4..])?;
                    let (attempts, disposition) = decode_handoff_suffix(record.rest)?;
                    if record.context.group_id != group_id {
                        continue;
                    }
                    apply_recovered_preparation(
                        &mut outbox,
                        group_id,
                        &record.context,
                        record.commitment,
                        record.ciphertext,
                        &payload_commitment,
                    )?;
                    let send = outbox.send_mut(&logical_id_from_context(&record.context)?)?;
                    let prior_attempts =
                        send.progress(&record.context.recipient)?.attempts_reserved;
                    if attempts != prior_attempts.checked_add(1).ok_or(Error::Malformed)? {
                        return Err(Error::Malformed);
                    }
                    let progress = send.reserve_handoff(&record.context.recipient)?;
                    if progress.attempts_reserved != attempts || progress.disposition != disposition
                    {
                        return Err(Error::Malformed);
                    }
                }
                b"TCGA" => {
                    let record = decode_progress_record(&entry[4..])?;
                    if !record.rest.is_empty() {
                        return Err(Error::Malformed);
                    }
                    if record.context.group_id != group_id {
                        continue;
                    }
                    apply_recovered_preparation(
                        &mut outbox,
                        group_id,
                        &record.context,
                        record.commitment,
                        record.ciphertext,
                        &payload_commitment,
                    )?;
                    let send = outbox.send_mut(&logical_id_from_context(&record.context)?)?;
                    if send.progress(&record.context.recipient)?.disposition
                        != RecipientDisposition::HandedOff
                    {
                        return Err(Error::WrongDisposition);
                    }
                    send.record_relay_accepted(&record.context.recipient)?;
                }
                _ if tag.starts_with(b"TCG") => return Err(Error::Malformed),
                _ => {}
            }
        }
        Ok(outbox)
    }
}

fn decode_intent_record(bytes: &[u8]) -> Result<LogicalSend, Error> {
    let (length, intent) = bytes.split_at_checked(4).ok_or(Error::Malformed)?;
    let length = usize::try_from(u32::from_be_bytes(
        length.try_into().map_err(|_| Error::Malformed)?,
    ))
    .map_err(|_| Error::Malformed)?;
    if intent.len() != length {
        return Err(Error::Malformed);
    }
    LogicalSend::decode_intent(intent)
}

fn logical_id_from_context(context: &ApplicationContext) -> Result<LogicalMessageId, Error> {
    LogicalMessageId::new(
        context.group_id,
        context.revision,
        context.sender.clone(),
        context.logical_sequence,
    )
}

struct ProgressRecord<'a> {
    context: ApplicationContext,
    commitment: [u8; DIGEST_LEN],
    ciphertext: Vec<u8>,
    rest: &'a [u8],
}

fn decode_progress_record(bytes: &[u8]) -> Result<ProgressRecord<'_>, Error> {
    fn take<'a>(cursor: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = cursor.split_at_checked(count).ok_or(Error::Malformed)?;
        *cursor = tail;
        Ok(head)
    }
    fn take_lp(cursor: &mut &[u8]) -> Result<Vec<u8>, Error> {
        let bytes = take(cursor, 4)?;
        let count = usize::try_from(u32::from_be_bytes(
            bytes.try_into().map_err(|_| Error::Malformed)?,
        ))
        .map_err(|_| Error::Malformed)?;
        Ok(take(cursor, count)?.to_vec())
    }

    let mut cursor = bytes;
    let context_bytes = take_lp(&mut cursor)?;
    let context = ApplicationContext::decode(&context_bytes)?;
    let commitment = take(&mut cursor, DIGEST_LEN)?
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let ciphertext = take_lp(&mut cursor)?;
    Ok(ProgressRecord {
        context,
        commitment,
        ciphertext,
        rest: cursor,
    })
}

fn decode_handoff_suffix(bytes: &[u8]) -> Result<(u8, RecipientDisposition), Error> {
    let [attempts, code] = bytes else {
        return Err(Error::Malformed);
    };
    let disposition = match code {
        0 => RecipientDisposition::HandedOff,
        1 => RecipientDisposition::ExhaustedUnknown,
        _ => return Err(Error::Malformed),
    };
    Ok((*attempts, disposition))
}

fn apply_recovered_preparation(
    outbox: &mut GroupOutbox,
    group_id: GroupId,
    context: &ApplicationContext,
    commitment: [u8; DIGEST_LEN],
    ciphertext: Vec<u8>,
    payload_commitment: &impl Fn(&[u8]) -> [u8; DIGEST_LEN],
) -> Result<(), Error> {
    if context.group_id != group_id {
        return Ok(());
    }
    let context_bytes = context.encode()?;
    if commitment != payload_commitment(&context_bytes) {
        return Err(Error::Conflict);
    }
    let send = outbox.send_mut(&logical_id_from_context(context)?)?;
    if send.application_context(&context.recipient)? != *context {
        return Err(Error::Conflict);
    }
    send.record_prepared(&context.recipient, commitment, ciphertext)?;
    Ok(())
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

    /// The canonical immutable intent that commits one logical ID before any
    /// recipient-specific pairwise operation begins.
    pub fn encode_intent(&self) -> Result<Vec<u8>, Error> {
        fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
            let len = u32::try_from(bytes.len()).map_err(|_| Error::Malformed)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
            Ok(())
        }
        fn put_member(out: &mut Vec<u8>, member: &Member) -> Result<(), Error> {
            put_lp(out, member.identity())?;
            put_lp(out, member.device())
        }

        let recipient_count = u32::try_from(self.recipients.len()).map_err(|_| Error::Malformed)?;
        let mut out = Vec::new();
        out.extend_from_slice(LOGICAL_SEND_DOMAIN);
        put_lp(&mut out, self.id.group_id.as_bytes())?;
        out.extend_from_slice(&self.id.revision.to_be_bytes());
        put_member(&mut out, &self.id.sender)?;
        out.extend_from_slice(&self.id.sequence.to_be_bytes());
        put_lp(&mut out, &self.roster_digest)?;
        put_lp(&mut out, &self.payload)?;
        out.extend_from_slice(&recipient_count.to_be_bytes());
        for progress in &self.recipients {
            put_member(&mut out, &progress.recipient)?;
        }
        Ok(out)
    }

    /// Recovers one immutable logical send from its canonical `TCGI` preimage.
    /// Mutable recipient progress is deliberately not encoded here: recovery
    /// replays later transcript records only after this immutable root passes
    /// every profile validation.
    pub fn decode_intent(bytes: &[u8]) -> Result<Self, Error> {
        fn take<'a>(cursor: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
            let (head, tail) = cursor.split_at_checked(count).ok_or(Error::Malformed)?;
            *cursor = tail;
            Ok(head)
        }
        fn take_u32(cursor: &mut &[u8]) -> Result<u32, Error> {
            Ok(u32::from_be_bytes(
                take(cursor, 4)?.try_into().map_err(|_| Error::Malformed)?,
            ))
        }
        fn take_u64(cursor: &mut &[u8]) -> Result<u64, Error> {
            Ok(u64::from_be_bytes(
                take(cursor, 8)?.try_into().map_err(|_| Error::Malformed)?,
            ))
        }
        fn take_lp(cursor: &mut &[u8]) -> Result<Vec<u8>, Error> {
            let length = usize::try_from(take_u32(cursor)?).map_err(|_| Error::Malformed)?;
            Ok(take(cursor, length)?.to_vec())
        }
        fn take_member(cursor: &mut &[u8]) -> Result<Member, Error> {
            let member = Member::new(take_lp(cursor)?, take_lp(cursor)?);
            member.validate()?;
            Ok(member)
        }

        let mut cursor = bytes;
        if !cursor.starts_with(LOGICAL_SEND_DOMAIN) {
            return Err(Error::Malformed);
        }
        cursor = &cursor[LOGICAL_SEND_DOMAIN.len()..];
        let group_id = GroupId::try_from(take_lp(&mut cursor)?.as_slice())?;
        let revision = take_u64(&mut cursor)?;
        let sender = take_member(&mut cursor)?;
        let sequence = take_u64(&mut cursor)?;
        let roster_digest: [u8; DIGEST_LEN] = take_lp(&mut cursor)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let payload = take_lp(&mut cursor)?;
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        let count = usize::try_from(take_u32(&mut cursor)?).map_err(|_| Error::Malformed)?;
        if count == 0 {
            return Err(Error::EmptyRecipients);
        }
        if count > MAX_MEMBERS {
            return Err(Error::TooManyMembers);
        }
        let recipients: Vec<Member> = (0..count)
            .map(|_| take_member(&mut cursor))
            .collect::<Result<_, _>>()?;
        if !cursor.is_empty() {
            return Err(Error::Malformed);
        }
        validate_recovery_recipients(&recipients)?;

        Ok(Self {
            id: LogicalMessageId::new(group_id, revision, sender, sequence)?,
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
            RecipientDisposition::HandedOff => {
                progress.disposition = RecipientDisposition::RelayAccepted;
                Ok(progress)
            }
            RecipientDisposition::Pending
            | RecipientDisposition::Prepared
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

fn validate_recovery_recipients(recipients: &[Member]) -> Result<(), Error> {
    let mut previous: Option<&Member> = None;
    let mut identities = BTreeSet::new();
    for recipient in recipients {
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
    fn canonical_intent_round_trips_to_pending_recipient_progress() {
        let original = send();
        let recovered = LogicalSend::decode_intent(&original.encode_intent().unwrap()).unwrap();

        assert_eq!(recovered, original);
        assert!(recovered.recipients().iter().all(|progress| {
            progress.disposition == RecipientDisposition::Pending
                && progress.context_commitment.is_none()
                && progress.ciphertext.is_none()
                && progress.attempts_reserved == 0
        }));
    }

    #[test]
    fn intent_recovery_refuses_noncanonical_or_trailing_recipient_data() {
        let mut reordered = send();
        reordered.recipients.swap(0, 1);
        assert_eq!(
            LogicalSend::decode_intent(&reordered.encode_intent().unwrap()),
            Err(Error::NonCanonical)
        );

        let mut trailing = send().encode_intent().unwrap();
        trailing.push(0);
        assert_eq!(LogicalSend::decode_intent(&trailing), Err(Error::Malformed));
    }

    fn test_payload_commitment(bytes: &[u8]) -> [u8; DIGEST_LEN] {
        let mut commitment = [0u8; DIGEST_LEN];
        for (index, byte) in bytes.iter().enumerate() {
            commitment[index % DIGEST_LEN] ^= byte;
        }
        commitment
    }

    fn progress_record(
        tag: &[u8; 4],
        context: &ApplicationContext,
        ciphertext: &[u8],
        suffix: &[u8],
    ) -> Vec<u8> {
        fn put_lp(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }

        let context = context.encode().unwrap();
        let mut record = tag.to_vec();
        put_lp(&mut record, &context);
        record.extend_from_slice(&test_payload_commitment(&context));
        put_lp(&mut record, ciphertext);
        record.extend_from_slice(suffix);
        record
    }

    fn intent_record(send: &LogicalSend) -> Vec<u8> {
        let intent = send.encode_intent().unwrap();
        let mut record = b"TCGI".to_vec();
        record.extend_from_slice(&(intent.len() as u32).to_be_bytes());
        record.extend_from_slice(&intent);
        record
    }

    #[test]
    fn outbox_recovery_replays_preparation_handoff_and_relay_acceptance() {
        let mut original = send();
        let context = original.application_context(&bob()).unwrap();
        let ciphertext = vec![1, 2, 3];
        original
            .record_prepared(
                &bob(),
                test_payload_commitment(&context.encode().unwrap()),
                ciphertext.clone(),
            )
            .unwrap();
        original.reserve_handoff(&bob()).unwrap();
        original.record_relay_accepted(&bob()).unwrap();

        let entries = vec![
            intent_record(&send()),
            progress_record(b"TCGP", &context, &ciphertext, &[]),
            progress_record(b"TCGH", &context, &ciphertext, &[1, 0]),
            progress_record(b"TCGA", &context, &ciphertext, &[]),
        ];
        let recovered =
            GroupOutbox::recover_from_transcript(group(), &entries, test_payload_commitment)
                .unwrap();

        assert_eq!(recovered.sends(), &[original]);
    }

    #[test]
    fn outbox_recovery_refuses_a_progress_record_with_the_wrong_commitment() {
        let original = send();
        let context = original.application_context(&bob()).unwrap();
        let entries = vec![
            intent_record(&original),
            progress_record(b"TCGP", &context, &[1, 2, 3], &[]),
        ];

        assert_eq!(
            GroupOutbox::recover_from_transcript(group(), &entries, |_| [0; DIGEST_LEN]),
            Err(Error::Conflict)
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
    fn relay_acceptance_requires_a_committed_handoff() {
        let mut logical_send = send();
        logical_send
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
            .unwrap();
        assert_eq!(
            logical_send.record_relay_accepted(&bob()),
            Err(Error::WrongDisposition)
        );
        logical_send.reserve_handoff(&bob()).unwrap();
        assert_eq!(
            logical_send
                .record_relay_accepted(&bob())
                .unwrap()
                .disposition,
            RecipientDisposition::RelayAccepted
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
            assert_eq!(
                outbox.record(send_at(sequence)),
                Ok(OutboxDisposition::Inserted)
            );
        }
        assert_eq!(outbox.record(send_at(8)), Err(Error::OutboxFull));

        outbox.cancel_for_newer_roster(3);
        for sequence in 8..=15 {
            assert_eq!(
                outbox.record(send_at(sequence)),
                Ok(OutboxDisposition::Inserted)
            );
        }
        assert_eq!(outbox.sends().len(), 16);
        assert_eq!(outbox.record(send_at(16)), Err(Error::OutboxFull));
    }

    #[test]
    fn outbox_retry_uses_the_committed_record_after_recipient_progresses() {
        let mut outbox = GroupOutbox::new(group());
        let original = send_at(4);
        assert_eq!(
            outbox.record(original.clone()),
            Ok(OutboxDisposition::Inserted)
        );
        outbox.sends[0]
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
            .unwrap();

        assert_eq!(outbox.record(original), Ok(OutboxDisposition::Duplicate));
        assert_eq!(
            outbox.sends()[0].recipients()[0].disposition,
            RecipientDisposition::Prepared
        );
        assert_eq!(
            outbox.sends()[0].recipients()[0].ciphertext,
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn logical_intent_is_canonical_and_excludes_recipient_progress() {
        let mut logical_send = send();
        let before = logical_send.encode_intent().unwrap();
        logical_send
            .record_prepared(&bob(), [1; DIGEST_LEN], vec![1, 2, 3])
            .unwrap();
        assert_eq!(logical_send.encode_intent(), Ok(before));
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
