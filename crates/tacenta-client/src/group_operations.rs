//! The client-side bridge between bounded group policy and the core helper.
//!
//! It does not perform pairwise encryption or transport. Its caller supplies
//! the ciphertext produced for the canonical application context, and this
//! module records the standalone core's commitment of that exact context with
//! the immutable recipient record before the durable coordinator can hand it
//! off.

use tacenta_core::crypto::{
    Address, CryptoStateEffect,
    groups::{payload_commitment, roster_commitment},
};
use tacenta_group::{
    ApplicationContext, Error as GroupError, GroupOutbox, GroupReceiver, LogicalMessageId,
    LogicalSend, Member, OutboxDisposition, ReceiveDisposition, ReceiveRefusal, RecipientProgress,
    RevalidatedReceive, Roster, RosterDisposition, RosterRefusal, RosterView,
};

use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};

/// A group preparation cannot cross its durable boundary.  The caller freezes
/// the affected operation and recovers its snapshot before it tries again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupOperationError {
    Policy,
    Frozen,
}

/// The durable result of a roster transition and its deferred-item replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RosterCommit {
    pub(crate) disposition: RosterDisposition,
    pub(crate) revalidated: Vec<RevalidatedReceive>,
}

/// The outcome data the live provider path supplies for one decrypted group
/// plaintext. The provider identity and crypto address are kept separate from
/// relay routing values until the adapter binds them to a `Member`.
pub(crate) struct GroupReceiveInput<'a> {
    pub(crate) plaintext: &'a [u8],
    pub(crate) authenticated_identity: &'a [u8],
    pub(crate) peer: &'a Address,
    pub(crate) provider_state: Vec<u8>,
    pub(crate) provider_effect: CryptoStateEffect,
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

/// Commits immutable group send intent before a caller can begin a
/// recipient-specific pairwise preparation. An exact duplicate observes the
/// existing logical record without publishing another snapshot generation.
pub(crate) fn commit_logical_intent<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    send: LogicalSend,
) -> Result<OutboxDisposition, GroupOperationError> {
    let intent = send
        .encode_intent()
        .map_err(|_| GroupOperationError::Policy)?;
    let mut candidate_outbox = outbox.clone();
    let disposition = candidate_outbox
        .record(send)
        .map_err(|_| GroupOperationError::Policy)?;
    if disposition == OutboxDisposition::Duplicate {
        return Ok(disposition);
    }

    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    candidate_snapshot
        .outbox
        .push(encode_intent_record(&intent)?);
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *outbox = candidate_outbox;
    Ok(disposition)
}

/// Rebuilds the in-memory group outbox from the exact durable outbox transcript.
/// The group policy codec owns its grammar while the client supplies the
/// standalone core's commitment domain.
pub(crate) fn recover_group_outbox(
    snapshot: &OperationSnapshot,
    group_id: tacenta_group::GroupId,
) -> Result<GroupOutbox, GroupOperationError> {
    GroupOutbox::recover_from_transcript(group_id, &snapshot.outbox, payload_commitment)
        .map_err(|_| GroupOperationError::Policy)
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
    provider_state: Vec<u8>,
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
    candidate_snapshot.provider_state = provider_state;

    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *logical_send = candidate_send;
    Ok(progress)
}

/// Prepares one recipient on the logical record already committed in the
/// group outbox. This is the durable path after `commit_logical_intent`.
pub(crate) fn commit_outbox_prepared_ciphertext<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    id: &LogicalMessageId,
    recipient: &Member,
    ciphertext: Vec<u8>,
    provider_state: Vec<u8>,
) -> Result<RecipientProgress, GroupOperationError> {
    let mut candidate_outbox = outbox.clone();
    let (progress, context) = {
        let send = candidate_outbox
            .send_mut(id)
            .map_err(|_| GroupOperationError::Policy)?;
        let progress = bind_prepared_ciphertext(send, recipient, ciphertext)
            .map_err(|_| GroupOperationError::Policy)?;
        let context = send
            .application_context(recipient)
            .map_err(|_| GroupOperationError::Policy)?
            .encode()
            .map_err(|_| GroupOperationError::Policy)?;
        (progress, context)
    };
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
    candidate_snapshot.provider_state = provider_state;
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *outbox = candidate_outbox;
    Ok(progress)
}

/// Reserves an exact prepared ciphertext attempt before returning it to a
/// transport caller. The caller may dispatch only the returned committed
/// record; a failed or uncertain commit exposes no handoff-eligible value.
pub(crate) fn commit_handoff_reservation<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    logical_send: &mut LogicalSend,
    recipient: &Member,
) -> Result<RecipientProgress, GroupOperationError> {
    let mut candidate_send = logical_send.clone();
    let progress = candidate_send
        .reserve_handoff(recipient)
        .map_err(|_| GroupOperationError::Policy)?
        .clone();
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
    candidate_snapshot.outbox.push(encode_handoff_record(
        &context,
        &commitment,
        ciphertext,
        &progress,
    )?);
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *logical_send = candidate_send;
    Ok(progress)
}

/// Reserves a handoff on an outbox-owned logical record. This keeps retries
/// tied to the immutable intent that was durably created first.
pub(crate) fn commit_outbox_handoff_reservation<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    id: &LogicalMessageId,
    recipient: &Member,
) -> Result<RecipientProgress, GroupOperationError> {
    let mut candidate_outbox = outbox.clone();
    let (progress, context) = {
        let send = candidate_outbox
            .send_mut(id)
            .map_err(|_| GroupOperationError::Policy)?;
        let progress = send
            .reserve_handoff(recipient)
            .map_err(|_| GroupOperationError::Policy)?
            .clone();
        let context = send
            .application_context(recipient)
            .map_err(|_| GroupOperationError::Policy)?
            .encode()
            .map_err(|_| GroupOperationError::Policy)?;
        (progress, context)
    };
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
    candidate_snapshot.outbox.push(encode_handoff_record(
        &context,
        &commitment,
        ciphertext,
        &progress,
    )?);
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *outbox = candidate_outbox;
    Ok(progress)
}

/// Records the relay's acceptance of an already handed-off ciphertext. This
/// is an observable transport result, never an application delivery receipt.
pub(crate) fn commit_outbox_relay_acceptance<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    id: &LogicalMessageId,
    recipient: &Member,
) -> Result<RecipientProgress, GroupOperationError> {
    let mut candidate_outbox = outbox.clone();
    let (progress, context) = {
        let send = candidate_outbox
            .send_mut(id)
            .map_err(|_| GroupOperationError::Policy)?;
        let progress = send
            .record_relay_accepted(recipient)
            .map_err(|_| GroupOperationError::Policy)?
            .clone();
        let context = send
            .application_context(recipient)
            .map_err(|_| GroupOperationError::Policy)?
            .encode()
            .map_err(|_| GroupOperationError::Policy)?;
        (progress, context)
    };
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
        .push(encode_relay_acceptance_record(
            &context,
            &commitment,
            ciphertext,
        )?);
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *outbox = candidate_outbox;
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

/// Binds pairwise-authenticated provider identity and device data to the
/// product member representation, then durably applies one group plaintext.
/// A malformed plaintext is a terminal disposition with no application event.
pub(crate) fn commit_group_plaintext<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    receiver: &mut GroupReceiver,
    input: GroupReceiveInput<'_>,
) -> Result<ReceiveDisposition, GroupOperationError> {
    let context = match ApplicationContext::decode(input.plaintext) {
        Ok(context) => context,
        Err(_) => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            return Ok(ReceiveDisposition::Rejected(ReceiveRefusal::Malformed));
        }
    };
    let authenticated_peer = Member::new(
        input.authenticated_identity.to_vec(),
        vec![input.peer.device],
    );
    commit_receive_disposition(
        store,
        snapshot,
        receiver,
        &context,
        &authenticated_peer,
        input.provider_state,
        input.provider_effect,
    )
}

fn commit_malformed_group_payload<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    plaintext: &[u8],
    provider_state: Vec<u8>,
    provider_effect: CryptoStateEffect,
) -> Result<(), GroupOperationError> {
    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    candidate_snapshot.provider_state = provider_state;
    candidate_snapshot
        .inbox
        .push(encode_malformed_record(provider_effect, plaintext)?);
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    Ok(())
}

/// Accepts or refuses one core-bound roster successor and records the control
/// disposition before exposing its membership effect. An accepted successor
/// stops incomplete sends from its older group revisions in the same commit.
pub(crate) fn commit_roster_successor<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    view: &mut RosterView,
    authenticated_authority: &Member,
    candidate: Roster,
    logical_sends: &mut [LogicalSend],
) -> Result<RosterDisposition, GroupOperationError> {
    Ok(commit_roster_transition(
        store,
        snapshot,
        view,
        None,
        authenticated_authority,
        candidate,
        logical_sends,
    )?
    .disposition)
}

/// As `commit_roster_successor`, while durably recording every revalidated
/// future item before returning its accepted event or terminal refusal.
pub(crate) fn commit_roster_successor_with_receiver<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    view: &mut RosterView,
    receiver: &mut GroupReceiver,
    authenticated_authority: &Member,
    candidate: Roster,
    logical_sends: &mut [LogicalSend],
) -> Result<RosterCommit, GroupOperationError> {
    commit_roster_transition(
        store,
        snapshot,
        view,
        Some(receiver),
        authenticated_authority,
        candidate,
        logical_sends,
    )
}

fn commit_roster_transition<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    view: &mut RosterView,
    receiver: Option<&mut GroupReceiver>,
    authenticated_authority: &Member,
    candidate: Roster,
    logical_sends: &mut [LogicalSend],
) -> Result<RosterCommit, GroupOperationError> {
    let preimage = candidate
        .encode()
        .map_err(|_| GroupOperationError::Policy)?;
    let commitment = roster_commitment(&preimage);
    let mut candidate_view = view.clone();
    let disposition =
        candidate_view.accept_successor(authenticated_authority, candidate.clone(), commitment);
    let mut candidate_sends = logical_sends.to_vec();
    if disposition == RosterDisposition::Accepted {
        for send in &mut candidate_sends {
            if send.id.group_id == candidate.group_id {
                send.cancel_for_newer_roster(candidate.revision);
            }
        }
    }

    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    candidate_snapshot.group_controls.push(encode_roster_record(
        &preimage,
        &commitment,
        disposition,
    )?);
    let mut candidate_receiver = receiver.as_deref().cloned();
    let revalidated = if disposition == RosterDisposition::Accepted {
        if let Some(receiver) = &mut candidate_receiver {
            let revalidated = receiver
                .install_accepted_roster(candidate.clone(), commitment)
                .map_err(|_| GroupOperationError::Policy)?;
            for item in &revalidated {
                let context = item
                    .context
                    .encode()
                    .map_err(|_| GroupOperationError::Policy)?;
                candidate_snapshot.inbox.push(encode_receive_record(
                    CryptoStateEffect::Unchanged,
                    &context,
                    &item.commitment,
                    item.disposition,
                )?);
                candidate_snapshot.dedup.push(context);
            }
            revalidated
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *view = candidate_view;
    logical_sends.clone_from_slice(&candidate_sends);
    if let (Some(receiver), Some(candidate_receiver)) = (receiver, candidate_receiver) {
        *receiver = candidate_receiver;
    }
    Ok(RosterCommit {
        disposition,
        revalidated,
    })
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

fn encode_intent_record(intent: &[u8]) -> Result<Vec<u8>, GroupOperationError> {
    let length = u32::try_from(intent.len()).map_err(|_| GroupOperationError::Policy)?;
    let mut record = Vec::with_capacity(8 + intent.len());
    record.extend_from_slice(b"TCGI");
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(intent);
    Ok(record)
}

fn encode_handoff_record(
    context: &[u8],
    commitment: &[u8; 32],
    ciphertext: &[u8],
    progress: &RecipientProgress,
) -> Result<Vec<u8>, GroupOperationError> {
    fn put_lp(out: &mut Vec<u8>, value: &[u8]) -> Result<(), GroupOperationError> {
        let length = u32::try_from(value.len()).map_err(|_| GroupOperationError::Policy)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value);
        Ok(())
    }
    let disposition = match progress.disposition {
        tacenta_group::RecipientDisposition::HandedOff => 0,
        tacenta_group::RecipientDisposition::ExhaustedUnknown => 1,
        _ => return Err(GroupOperationError::Policy),
    };
    let mut record = Vec::new();
    record.extend_from_slice(b"TCGH");
    put_lp(&mut record, context)?;
    record.extend_from_slice(commitment);
    put_lp(&mut record, ciphertext)?;
    record.push(progress.attempts_reserved);
    record.push(disposition);
    Ok(record)
}

fn encode_relay_acceptance_record(
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
    record.extend_from_slice(b"TCGA");
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
            ReceiveRefusal::Malformed => 0,
            ReceiveRefusal::WrongPeer => 1,
            ReceiveRefusal::WrongGroup => 2,
            ReceiveRefusal::WrongRecipient => 3,
            ReceiveRefusal::NotActive => 4,
            ReceiveRefusal::OldRevision => 5,
            ReceiveRefusal::InvalidRoster => 6,
            ReceiveRefusal::FutureOutOfRange => 7,
            ReceiveRefusal::SequenceExpired => 8,
            ReceiveRefusal::Conflict => 9,
            ReceiveRefusal::DeferredFull => 10,
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

fn encode_malformed_record(
    provider_effect: CryptoStateEffect,
    plaintext: &[u8],
) -> Result<Vec<u8>, GroupOperationError> {
    let length = u32::try_from(plaintext.len()).map_err(|_| GroupOperationError::Policy)?;
    let effect = match provider_effect {
        CryptoStateEffect::Unchanged => 0,
        CryptoStateEffect::Advanced => 1,
        CryptoStateEffect::Terminal => 2,
    };
    let mut record = Vec::with_capacity(9 + plaintext.len());
    record.extend_from_slice(b"TCGM");
    record.push(effect);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(plaintext);
    Ok(record)
}

fn encode_roster_record(
    preimage: &[u8],
    commitment: &[u8; 32],
    disposition: RosterDisposition,
) -> Result<Vec<u8>, GroupOperationError> {
    fn put_lp(out: &mut Vec<u8>, value: &[u8]) -> Result<(), GroupOperationError> {
        let length = u32::try_from(value.len()).map_err(|_| GroupOperationError::Policy)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value);
        Ok(())
    }
    fn refusal_code(refusal: RosterRefusal) -> u8 {
        match refusal {
            RosterRefusal::WrongAuthority => 0,
            RosterRefusal::WrongGroup => 1,
            RosterRefusal::InvalidGenesis => 2,
            RosterRefusal::StaleRevision => 3,
            RosterRefusal::MissingPredecessor => 4,
            RosterRefusal::Conflict => 5,
            RosterRefusal::AuthorityTransfer => 6,
            RosterRefusal::PolicyChange => 7,
            RosterRefusal::Reopened => 8,
            RosterRefusal::MissingAuthorityMember => 9,
        }
    }

    let mut record = Vec::new();
    record.extend_from_slice(b"TCGC");
    put_lp(&mut record, preimage)?;
    record.extend_from_slice(commitment);
    match disposition {
        RosterDisposition::Accepted => record.push(0),
        RosterDisposition::Duplicate => record.push(1),
        RosterDisposition::Rejected(refusal) => {
            record.push(2);
            record.push(refusal_code(refusal));
        }
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::{
        GroupOperationError, GroupReceiveInput, bind_prepared_ciphertext, commit_group_plaintext,
        commit_handoff_reservation, commit_logical_intent, commit_outbox_handoff_reservation,
        commit_outbox_prepared_ciphertext, commit_outbox_relay_acceptance,
        commit_prepared_ciphertext, commit_receive_disposition, commit_roster_successor,
        commit_roster_successor_with_receiver, recover_group_outbox,
    };
    use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};
    use tacenta_core::crypto::{Address, CryptoStateEffect};
    use tacenta_group::{
        ApplicationContext, DIGEST_LEN, GroupId, GroupOutbox, GroupReceiver, LogicalSend, Member,
        OutboxDisposition, POLICY_VERSION_V1, ReceiveDisposition, ReceiveRefusal,
        RecipientDisposition, Roster, RosterDisposition, RosterView,
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

    fn roster(revision: u64, predecessor: [u8; DIGEST_LEN], members: Vec<Member>) -> Roster {
        Roster::new(
            GroupId::new(*b"bounded-group-id"),
            revision,
            predecessor,
            alice(),
            POLICY_VERSION_V1,
            false,
            members,
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

    #[test]
    fn logical_intent_commits_once_before_recipient_preparation() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = GroupOutbox::new(GroupId::new(*b"bounded-group-id"));
        let send = logical_send();

        assert_eq!(
            commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send.clone()),
            Ok(OutboxDisposition::Inserted)
        );
        assert_eq!(snapshot.generation, 5);
        assert_eq!(&snapshot.outbox[0][..4], b"TCGI");
        assert_eq!(outbox.sends().len(), 1);
        assert_eq!(
            commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send),
            Ok(OutboxDisposition::Duplicate)
        );
        assert_eq!(snapshot.generation, 5);
    }

    #[test]
    fn unknown_logical_intent_commit_freezes_without_adding_live_outbox_state() {
        let mut store = Store {
            outcome: CommitOutcome::Unknown,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let before_snapshot = snapshot.clone();
        let mut outbox = GroupOutbox::new(GroupId::new(*b"bounded-group-id"));

        assert_eq!(
            commit_logical_intent(&mut store, &mut snapshot, &mut outbox, logical_send()),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(snapshot, before_snapshot);
        assert!(outbox.sends().is_empty());
    }

    #[test]
    fn outbox_owned_progress_keeps_intent_preparation_and_handoff_together() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = GroupOutbox::new(GroupId::new(*b"bounded-group-id"));
        let send = logical_send();
        let id = send.id.clone();
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();

        assert_eq!(
            commit_outbox_prepared_ciphertext(
                &mut store,
                &mut snapshot,
                &mut outbox,
                &id,
                &bob(),
                vec![7, 8],
                vec![4, 5, 6],
            )
            .unwrap()
            .ciphertext,
            Some(vec![7, 8])
        );
        assert_eq!(
            commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &bob(),)
                .unwrap()
                .disposition,
            RecipientDisposition::HandedOff
        );
        assert_eq!(
            commit_outbox_relay_acceptance(&mut store, &mut snapshot, &mut outbox, &id, &bob(),)
                .unwrap()
                .disposition,
            RecipientDisposition::RelayAccepted
        );
        assert_eq!(
            outbox.send(&id).unwrap().recipients()[0].attempts_reserved,
            1
        );
        assert_eq!(&snapshot.outbox[0][..4], b"TCGI");
        assert_eq!(&snapshot.outbox[1][..4], b"TCGP");
        assert_eq!(snapshot.provider_state, vec![4, 5, 6]);
        assert_eq!(&snapshot.outbox[2][..4], b"TCGH");
        assert_eq!(&snapshot.outbox[3][..4], b"TCGA");
    }

    #[test]
    fn unknown_outbox_progress_commit_leaves_the_committed_send_unchanged() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = GroupOutbox::new(GroupId::new(*b"bounded-group-id"));
        let send = logical_send();
        let id = send.id.clone();
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
        store.outcome = CommitOutcome::Unknown;
        let before_snapshot = snapshot.clone();
        let before_outbox = outbox.clone();

        assert_eq!(
            commit_outbox_prepared_ciphertext(
                &mut store,
                &mut snapshot,
                &mut outbox,
                &id,
                &bob(),
                vec![7, 8],
                vec![4, 5, 6],
            ),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(snapshot, before_snapshot);
        assert_eq!(outbox, before_outbox);
    }

    #[test]
    fn unknown_relay_acceptance_commit_keeps_the_handoff_pending() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = GroupOutbox::new(GroupId::new(*b"bounded-group-id"));
        let send = logical_send();
        let id = send.id.clone();
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
        commit_outbox_prepared_ciphertext(
            &mut store,
            &mut snapshot,
            &mut outbox,
            &id,
            &bob(),
            vec![7, 8],
            vec![4, 5, 6],
        )
        .unwrap();
        commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &bob())
            .unwrap();
        store.outcome = CommitOutcome::Unknown;
        let before_snapshot = snapshot.clone();
        let before_outbox = outbox.clone();

        assert_eq!(
            commit_outbox_relay_acceptance(&mut store, &mut snapshot, &mut outbox, &id, &bob()),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(snapshot, before_snapshot);
        assert_eq!(outbox, before_outbox);
        assert_eq!(
            outbox.send(&id).unwrap().recipients()[0].disposition,
            RecipientDisposition::HandedOff
        );
    }

    #[test]
    fn core_bound_outbox_transcript_recovers_the_exact_recipient_progress() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = GroupOutbox::new(GroupId::new(*b"bounded-group-id"));
        let send = logical_send();
        let id = send.id.clone();
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
        commit_outbox_prepared_ciphertext(
            &mut store,
            &mut snapshot,
            &mut outbox,
            &id,
            &bob(),
            vec![7, 8],
            vec![4, 5, 6],
        )
        .unwrap();
        commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &bob())
            .unwrap();
        commit_outbox_relay_acceptance(&mut store, &mut snapshot, &mut outbox, &id, &bob())
            .unwrap();

        assert_eq!(
            recover_group_outbox(&snapshot, GroupId::new(*b"bounded-group-id")),
            Ok(outbox)
        );
    }

    #[test]
    fn handoff_reservation_commits_exact_prepared_bytes_before_returning_them() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut send = logical_send();
        commit_prepared_ciphertext(
            &mut store,
            &mut snapshot,
            &mut send,
            &bob(),
            vec![7, 8],
            vec![4, 5, 6],
        )
        .unwrap();

        let progress =
            commit_handoff_reservation(&mut store, &mut snapshot, &mut send, &bob()).unwrap();
        assert_eq!(progress.attempts_reserved, 1);
        assert_eq!(progress.ciphertext, Some(vec![7, 8]));
        assert_eq!(progress.disposition, RecipientDisposition::HandedOff);
        assert_eq!(&snapshot.outbox[1][..4], b"TCGH");
    }

    #[test]
    fn unknown_handoff_reservation_does_not_expose_a_new_attempt() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut send = logical_send();
        commit_prepared_ciphertext(
            &mut store,
            &mut snapshot,
            &mut send,
            &bob(),
            vec![7, 8],
            vec![4, 5, 6],
        )
        .unwrap();
        store.outcome = CommitOutcome::Unknown;
        let before_snapshot = snapshot.clone();
        let before_send = send.clone();

        assert_eq!(
            commit_handoff_reservation(&mut store, &mut snapshot, &mut send, &bob()),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(snapshot, before_snapshot);
        assert_eq!(send, before_send);
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
        let progress = commit_prepared_ciphertext(
            &mut store,
            &mut snapshot,
            &mut send,
            &bob(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        )
        .unwrap();

        assert_eq!(snapshot.generation, 5);
        assert_eq!(store.recover().unwrap(), Some(snapshot.clone()));
        assert_eq!(progress.ciphertext, Some(vec![1, 2, 3]));
        assert_eq!(snapshot.provider_state, vec![4, 5, 6]);
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
            commit_prepared_ciphertext(
                &mut store,
                &mut snapshot,
                &mut send,
                &bob(),
                vec![1],
                vec![4, 5, 6],
            ),
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
    fn provider_bound_group_plaintext_uses_identity_and_crypto_device() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(2);
        let mut receiver = receiver();

        assert_eq!(
            commit_group_plaintext(
                &mut store,
                &mut snapshot,
                &mut receiver,
                GroupReceiveInput {
                    plaintext: &receive_context().encode().unwrap(),
                    authenticated_identity: b"alice-key",
                    peer: &Address::new("alice", 1),
                    provider_state: vec![9],
                    provider_effect: CryptoStateEffect::Advanced,
                },
            ),
            Ok(ReceiveDisposition::Accepted { event_id: 0 })
        );
    }

    #[test]
    fn malformed_group_plaintext_retains_terminal_provider_state_before_ack() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(2);
        let mut receiver = receiver();

        assert_eq!(
            commit_group_plaintext(
                &mut store,
                &mut snapshot,
                &mut receiver,
                GroupReceiveInput {
                    plaintext: b"not a group context",
                    authenticated_identity: b"alice-key",
                    peer: &Address::new("alice", 1),
                    provider_state: vec![9],
                    provider_effect: CryptoStateEffect::Terminal,
                },
            ),
            Ok(ReceiveDisposition::Rejected(ReceiveRefusal::Malformed))
        );
        assert_eq!(snapshot.provider_state, vec![9]);
        assert_eq!(&snapshot.inbox[0][..5], b"TCGM\x02");
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

    #[test]
    fn accepted_roster_successor_cancels_old_handoffs_in_its_same_commit() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let mut view = RosterView::accept_genesis(
            &alice(),
            genesis,
            tacenta_core::crypto::groups::roster_commitment(
                &roster(0, [0; DIGEST_LEN], vec![alice()]).encode().unwrap(),
            ),
        )
        .unwrap();
        let r1 = roster(1, *view.digest(), vec![alice(), bob()]);
        let r1_commitment = tacenta_core::crypto::groups::roster_commitment(&r1.encode().unwrap());
        assert_eq!(
            view.accept_successor(&alice(), r1, r1_commitment),
            RosterDisposition::Accepted
        );
        let r2 = roster(2, *view.digest(), vec![alice()]);
        let mut send = logical_send();
        send.record_prepared(&bob(), [3; DIGEST_LEN], vec![8])
            .unwrap();
        send.reserve_handoff(&bob()).unwrap();
        let mut sends = vec![send];
        let mut snapshot = OperationSnapshot::empty(4);
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };

        assert_eq!(
            commit_roster_successor(
                &mut store,
                &mut snapshot,
                &mut view,
                &alice(),
                r2,
                &mut sends,
            ),
            Ok(RosterDisposition::Accepted)
        );
        assert_eq!(snapshot.generation, 5);
        assert_eq!(&snapshot.group_controls[0][..4], b"TCGC");
        assert_eq!(
            sends[0].recipients()[0].disposition,
            RecipientDisposition::CancelledAfterHandoff
        );
        assert_eq!(store.recover().unwrap(), Some(snapshot));
    }

    #[test]
    fn uncertain_roster_commit_keeps_the_active_view_and_handoff_live() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment =
            tacenta_core::crypto::groups::roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_commitment).unwrap();
        let candidate = roster(1, *view.digest(), vec![alice(), bob()]);
        let mut sends = vec![logical_send()];
        let before_view = view.clone();
        let before_sends = sends.clone();
        let mut snapshot = OperationSnapshot::empty(4);
        let before_snapshot = snapshot.clone();
        let mut store = Store {
            outcome: CommitOutcome::Unknown,
            committed: None,
        };

        assert_eq!(
            commit_roster_successor(
                &mut store,
                &mut snapshot,
                &mut view,
                &alice(),
                candidate,
                &mut sends,
            ),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(view, before_view);
        assert_eq!(sends, before_sends);
        assert_eq!(snapshot, before_snapshot);
    }

    #[test]
    fn roster_commit_revalidates_future_items_before_returning_their_events() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment =
            tacenta_core::crypto::groups::roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_commitment).unwrap();
        let r1 = roster(1, *view.digest(), vec![alice(), bob()]);
        let r1_commitment = tacenta_core::crypto::groups::roster_commitment(&r1.encode().unwrap());
        assert_eq!(
            view.accept_successor(&alice(), r1.clone(), r1_commitment),
            RosterDisposition::Accepted
        );
        let r2 = roster(2, *view.digest(), vec![alice(), bob()]);
        let r2_commitment = tacenta_core::crypto::groups::roster_commitment(&r2.encode().unwrap());
        let mut receiver = GroupReceiver::new(r1, r1_commitment, bob());
        let future = ApplicationContext::new(
            GroupId::new(*b"bounded-group-id"),
            2,
            r2_commitment,
            alice(),
            bob(),
            8,
            b"hello".to_vec(),
        )
        .unwrap();
        assert_eq!(
            receiver.receive(&future, &alice(), [7; DIGEST_LEN]),
            ReceiveDisposition::Deferred
        );
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(1);
        let mut sends = Vec::new();

        let result = commit_roster_successor_with_receiver(
            &mut store,
            &mut snapshot,
            &mut view,
            &mut receiver,
            &alice(),
            r2,
            &mut sends,
        )
        .unwrap();
        assert_eq!(result.disposition, RosterDisposition::Accepted);
        assert_eq!(
            result.revalidated[0].disposition,
            ReceiveDisposition::Accepted { event_id: 0 }
        );
        assert_eq!(snapshot.inbox.len(), 1);
        assert_eq!(&snapshot.inbox[0][..5], b"TCGR\x00");
        assert_eq!(store.recover().unwrap(), Some(snapshot));
    }
}
