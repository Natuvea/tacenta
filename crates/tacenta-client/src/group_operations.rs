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
    ApplicationContext, Error as GroupError, GroupOutbox, GroupPayload, GroupReceiver,
    InvitationBook, InvitationBootstrap, InvitationId, InvitationStatus, LogicalMessageId,
    LogicalSend, Member, OutboxDisposition, ReceiveDisposition, ReceiveRefusal, RecipientProgress,
    RevalidatedReceive, Roster, RosterDisposition, RosterRefusal, RosterView,
};

use crate::group_control_outbox::{
    Disposition as ControlDisposition, Handoff as ControlHandoff, Outbox as ControlOutbox,
};
use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};
use crate::{Client, ErrorKind};

const MAX_GROUP_CONTROL_RECORDS: usize = 64;

/// A group preparation cannot cross its durable boundary.  The caller freezes
/// the affected operation and recovers its snapshot before it tries again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupOperationError {
    Policy,
    Frozen,
}

/// The live group coordinator distinguishes an unchanged transport handoff
/// from an operation that must freeze after a durable or provider boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupLiveError {
    Policy,
    Frozen,
    Transport,
}

impl From<GroupOperationError> for GroupLiveError {
    fn from(error: GroupOperationError) -> Self {
        match error {
            GroupOperationError::Policy => Self::Policy,
            GroupOperationError::Frozen => Self::Frozen,
        }
    }
}

fn live_client_error(kind: ErrorKind) -> GroupLiveError {
    match kind {
        ErrorKind::Network | ErrorKind::RateLimited => GroupLiveError::Transport,
        _ => GroupLiveError::Frozen,
    }
}

/// The durable result of a roster transition and its deferred-item replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RosterCommit {
    pub(crate) disposition: RosterDisposition,
    pub(crate) revalidated: Vec<RevalidatedReceive>,
}

/// The durable effect selected by the canonical inner group payload tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GroupPayloadDisposition {
    Application(ReceiveDisposition),
    Roster(RosterCommit),
}

struct RosterCommitState<'a> {
    view: &'a mut RosterView,
    receiver: Option<&'a mut GroupReceiver>,
    provider: Option<(Vec<u8>, CryptoStateEffect)>,
    control_outbox: Option<&'a mut ControlOutbox>,
    prepared_control: Option<PreparedControl>,
    invitation_book: Option<&'a mut InvitationBook>,
    admission: Option<InvitationAdmission>,
}

#[derive(Clone, Debug)]
struct PreparedControl {
    recipient: Member,
    payload: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct InvitationAdmission {
    pub(crate) id: InvitationId,
    pub(crate) target: Member,
    pub(crate) now: u64,
}

fn recipient_can_receive_roster_control(
    view: &RosterView,
    successor: &Roster,
    recipient: &Member,
) -> bool {
    view.roster()
        .members
        .iter()
        .any(|member| member == recipient)
        || successor.members.iter().any(|member| member == recipient)
}

fn recipient_can_receive_installed_roster_control(
    view: &RosterView,
    authenticated_authority: &Member,
    recipient: &Member,
) -> bool {
    &view.roster().authority == authenticated_authority
        && view
            .roster()
            .members
            .iter()
            .any(|member| member == recipient)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityRosterControlCommit {
    pub(crate) roster: RosterCommit,
    pub(crate) handoff: ControlHandoff,
}

pub(crate) struct AuthorityControlState<'a> {
    pub(crate) view: &'a mut RosterView,
    pub(crate) receiver: &'a mut GroupReceiver,
    pub(crate) logical_sends: &'a mut [LogicalSend],
    pub(crate) outbox: &'a mut ControlOutbox,
    pub(crate) invitation_book: Option<&'a mut InvitationBook>,
    pub(crate) admission: Option<InvitationAdmission>,
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

/// Restores the bounded receiver's stable event and deferred state from the
/// combined snapshot, verifying every retained core commitment on the way in.
pub(crate) fn recover_group_receiver(
    snapshot: &OperationSnapshot,
) -> Result<GroupReceiver, GroupOperationError> {
    GroupReceiver::decode_state(
        &snapshot.application_state,
        roster_commitment,
        payload_commitment,
    )
    .map_err(|_| GroupOperationError::Policy)
}

/// Restores the latest core-verified roster checkpoint from the durable control
/// transcript. The authority comes from the bootstrap channel, never a record.
pub(crate) fn recover_group_roster_view(
    snapshot: &OperationSnapshot,
    pinned_authority: &Member,
) -> Result<RosterView, GroupOperationError> {
    let Some(record) = snapshot
        .group_controls
        .iter()
        .rev()
        .find(|record| record.starts_with(b"TCGV"))
    else {
        return Err(GroupOperationError::Policy);
    };
    let state = decode_roster_view_record(record)?;
    RosterView::decode_state(state, pinned_authority, roster_commitment)
        .map_err(|_| GroupOperationError::Policy)
}

/// Restores the latest bounded invitation lifecycle checkpoint for one group.
/// A group ID comes from the caller's selected coordinator, never from the
/// retained bytes alone.
pub(crate) fn recover_group_invitation_book(
    snapshot: &OperationSnapshot,
    group_id: tacenta_group::GroupId,
) -> Result<InvitationBook, GroupOperationError> {
    let Some(record) = snapshot
        .group_controls
        .iter()
        .rev()
        .find(|record| record.starts_with(b"TCGB"))
    else {
        return Err(GroupOperationError::Policy);
    };
    InvitationBook::decode_state(decode_invitation_book_record(record)?, group_id)
        .map_err(|_| GroupOperationError::Policy)
}

/// Restores the latest exact-ciphertext roster-control handoff checkpoint.
pub(crate) fn recover_group_control_outbox(
    snapshot: &OperationSnapshot,
) -> Result<ControlOutbox, GroupOperationError> {
    let Some(record) = snapshot
        .group_controls
        .iter()
        .rev()
        .find(|record| record.starts_with(b"TCGO"))
    else {
        return Ok(ControlOutbox::default());
    };
    ControlOutbox::decode_state(decode_control_outbox_record(record)?)
        .map_err(|_| GroupOperationError::Policy)
}

/// Publishes one bounded roster-control handoff transition before exposing its
/// prepared ciphertext, retry reservation, or relay-acceptance result.
pub(crate) fn commit_group_control_outbox_transition<S, T>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut ControlOutbox,
    transition: impl FnOnce(&mut ControlOutbox) -> Result<T, GroupError>,
) -> Result<T, GroupOperationError>
where
    S: OperationStore,
{
    let mut candidate_outbox = outbox.clone();
    let result = transition(&mut candidate_outbox).map_err(|_| GroupOperationError::Policy)?;
    let state = candidate_outbox
        .encode_state()
        .map_err(|_| GroupOperationError::Policy)?;
    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    append_group_control_records(
        &mut candidate_snapshot,
        [encode_control_outbox_record(&state)?],
    );
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *outbox = candidate_outbox;
    Ok(result)
}

fn commit_prepared_control_handoff<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut ControlOutbox,
    recipient: Member,
    payload: Vec<u8>,
    ciphertext: Vec<u8>,
    provider_state: Vec<u8>,
) -> Result<ControlHandoff, GroupOperationError> {
    let mut candidate_outbox = outbox.clone();
    candidate_outbox
        .record_prepared(recipient.clone(), payload.clone(), ciphertext)
        .map_err(|_| GroupOperationError::Policy)?;
    let state = candidate_outbox
        .encode_state()
        .map_err(|_| GroupOperationError::Policy)?;
    let handoff = candidate_outbox
        .handoff(&recipient, &payload)
        .map_err(|_| GroupOperationError::Policy)?;
    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    candidate_snapshot.provider_state = provider_state;
    append_group_control_records(
        &mut candidate_snapshot,
        [encode_control_outbox_record(&state)?],
    );
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *outbox = candidate_outbox;
    Ok(handoff)
}

/// Encrypts one canonical roster successor for an authenticated recipient and
/// persists its exact ciphertext with the advanced provider state before any
/// relay request can occur.
pub(crate) async fn prepare_outbound_roster_control<P, S>(
    client: &mut Client<P>,
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut ControlOutbox,
    recipient: &Member,
    route: &tacenta_relay::DeviceAddr,
    successor: Roster,
) -> Result<ControlHandoff, GroupLiveError>
where
    P: tacenta_core::crypto::CryptoProvider,
    S: OperationStore,
{
    let payload = GroupPayload::Roster(successor)
        .encode()
        .map_err(|_| GroupLiveError::Policy)?;
    let (ciphertext, provider_state) = client
        .prepare_group_ciphertext(route, recipient.identity(), &payload)
        .await
        .map_err(|error| live_client_error(error.kind()))?;
    commit_prepared_control_handoff(
        store,
        snapshot,
        outbox,
        recipient.clone(),
        payload,
        ciphertext,
        provider_state,
    )
    .map_err(Into::into)
}

/// Prepares an authority's roster successor and commits its local membership
/// effect, provider state, and exact recipient ciphertext in one snapshot.
pub(crate) async fn prepare_authority_roster_control<P, S>(
    client: &mut Client<P>,
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    state: AuthorityControlState<'_>,
    authenticated_authority: &Member,
    recipient_route: (&Member, &tacenta_relay::DeviceAddr),
    successor: Roster,
) -> Result<AuthorityRosterControlCommit, GroupLiveError>
where
    P: tacenta_core::crypto::CryptoProvider,
    S: OperationStore,
{
    let (recipient, route) = recipient_route;
    if client.party.identity_key() != authenticated_authority.identity() {
        return Err(GroupLiveError::Policy);
    }
    if !recipient_can_receive_roster_control(state.view, &successor, recipient) {
        return Err(GroupLiveError::Policy);
    }
    let preimage = successor.encode().map_err(|_| GroupLiveError::Policy)?;
    let mut preflight = state.view.clone();
    if preflight.accept_successor(
        authenticated_authority,
        successor.clone(),
        roster_commitment(&preimage),
    ) != RosterDisposition::Accepted
    {
        return Err(GroupLiveError::Policy);
    }
    let payload = GroupPayload::Roster(successor.clone())
        .encode()
        .map_err(|_| GroupLiveError::Policy)?;
    let (ciphertext, provider_state) = client
        .prepare_group_ciphertext(route, recipient.identity(), &payload)
        .await
        .map_err(|error| live_client_error(error.kind()))?;
    let roster = commit_roster_transition(
        store,
        snapshot,
        RosterCommitState {
            view: &mut *state.view,
            receiver: Some(&mut *state.receiver),
            provider: Some((provider_state, CryptoStateEffect::Advanced)),
            control_outbox: Some(&mut *state.outbox),
            prepared_control: Some(PreparedControl {
                recipient: recipient.clone(),
                payload: payload.clone(),
                ciphertext,
            }),
            invitation_book: state.invitation_book.map(|book| &mut *book),
            admission: state.admission,
        },
        authenticated_authority,
        successor,
        &mut *state.logical_sends,
    )
    .map_err(GroupLiveError::from)?;
    let handoff = state
        .outbox
        .handoff(recipient, &payload)
        .map_err(|_| GroupLiveError::Frozen)?;
    Ok(AuthorityRosterControlCommit { roster, handoff })
}

/// Prepares another exact ciphertext for the authority's already-installed
/// roster. This supports fan-out without allowing a second local transition.
pub(crate) async fn prepare_installed_roster_control<P, S>(
    client: &mut Client<P>,
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    view: &RosterView,
    outbox: &mut ControlOutbox,
    authenticated_authority: &Member,
    recipient_route: (&Member, &tacenta_relay::DeviceAddr),
) -> Result<ControlHandoff, GroupLiveError>
where
    P: tacenta_core::crypto::CryptoProvider,
    S: OperationStore,
{
    let (recipient, route) = recipient_route;
    if client.party.identity_key() != authenticated_authority.identity()
        || !recipient_can_receive_installed_roster_control(view, authenticated_authority, recipient)
    {
        return Err(GroupLiveError::Policy);
    }
    prepare_outbound_roster_control(
        client,
        store,
        snapshot,
        outbox,
        recipient,
        route,
        view.roster().clone(),
    )
    .await
}

/// Reserves and sends an already committed roster-control ciphertext. A
/// transport failure keeps the reserved exact bytes in the durable checkpoint.
pub(crate) async fn dispatch_outbound_roster_control<P, S>(
    client: &mut Client<P>,
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut ControlOutbox,
    recipient: &Member,
    payload: &[u8],
    route: &tacenta_relay::DeviceAddr,
) -> Result<ControlHandoff, GroupLiveError>
where
    P: tacenta_core::crypto::CryptoProvider,
    S: OperationStore,
{
    let handoff = commit_group_control_outbox_transition(store, snapshot, outbox, |candidate| {
        candidate.reserve(recipient, payload)
    })
    .map_err(GroupLiveError::from)?;
    if handoff.disposition == ControlDisposition::ExhaustedUnknown {
        return Err(GroupLiveError::Frozen);
    }
    client
        .dispatch_group_ciphertext(route, &handoff.ciphertext)
        .await
        .map_err(|error| live_client_error(error.kind()))?;
    commit_group_control_outbox_transition(store, snapshot, outbox, |candidate| {
        candidate.accept(recipient, payload)
    })
    .map_err(GroupLiveError::from)?;
    outbox
        .handoff(recipient, payload)
        .map_err(|_| GroupLiveError::Policy)
}

/// Applies an invitation lifecycle operation to a cloned book and publishes
/// its canonical checkpoint before exposing the resulting disposition.
pub(crate) fn commit_group_invitation_transition<S, T>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    book: &mut InvitationBook,
    transition: impl FnOnce(&mut InvitationBook) -> Result<T, GroupError>,
) -> Result<T, GroupOperationError>
where
    S: OperationStore,
{
    commit_group_invitation_transition_with_provider(store, snapshot, book, None, transition)
}

fn commit_group_invitation_transition_with_provider<S, T>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    book: &mut InvitationBook,
    provider: Option<(Vec<u8>, CryptoStateEffect)>,
    transition: impl FnOnce(&mut InvitationBook) -> Result<T, GroupError>,
) -> Result<T, GroupOperationError>
where
    S: OperationStore,
{
    let mut candidate_book = book.clone();
    let result = transition(&mut candidate_book).map_err(|_| GroupOperationError::Policy)?;
    let state = candidate_book
        .encode_state()
        .map_err(|_| GroupOperationError::Policy)?;
    let mut candidate_snapshot = snapshot.clone();
    candidate_snapshot.generation = candidate_snapshot
        .generation
        .checked_add(1)
        .ok_or(GroupOperationError::Frozen)?;
    let mut records = vec![encode_invitation_book_record(&state)?];
    if let Some((provider_state, provider_effect)) = provider {
        candidate_snapshot.provider_state = provider_state;
        records.push(encode_control_effect_record(provider_effect));
    }
    append_group_control_records(&mut candidate_snapshot, records);
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *book = candidate_book;
    Ok(result)
}

/// Records an authenticated invitation bootstrap before exposing the source
/// roster to the caller. The caller obtains the returned source roster only
/// after this group-scoped lifecycle checkpoint commits.
pub(crate) fn commit_group_invitation_bootstrap<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    book: &mut InvitationBook,
    local_member: &Member,
    now: u64,
    input: GroupReceiveInput<'_>,
) -> Result<InvitationBootstrap, GroupOperationError> {
    let bootstrap = match GroupPayload::decode(input.plaintext) {
        Ok(GroupPayload::InvitationBootstrap(bootstrap)) => bootstrap,
        _ => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            return Err(GroupOperationError::Policy);
        }
    };
    let authenticated_peer = Member::new(
        input.authenticated_identity.to_vec(),
        vec![input.peer.device],
    );
    let source_digest = roster_commitment(
        &bootstrap
            .source_roster
            .encode()
            .map_err(|_| GroupOperationError::Policy)?,
    );
    if bootstrap.validate_source_digest(&source_digest).is_err()
        || bootstrap.source_roster.closed
        || bootstrap.source_roster.authority != authenticated_peer
        || &bootstrap.invitation.target != local_member
    {
        commit_malformed_group_payload(
            store,
            snapshot,
            input.plaintext,
            input.provider_state,
            input.provider_effect,
        )?;
        return Err(GroupOperationError::Policy);
    }
    let result = commit_group_invitation_transition_with_provider(
        store,
        snapshot,
        book,
        Some((input.provider_state.clone(), input.provider_effect)),
        |candidate| {
            candidate
                .create(
                    &authenticated_peer,
                    &bootstrap.source_roster.authority,
                    &bootstrap.source_roster.members,
                    bootstrap.invitation.clone(),
                    now,
                )
                .map(|_| bootstrap.clone())
        },
    );
    match result {
        Ok(bootstrap) => Ok(bootstrap),
        Err(GroupOperationError::Policy) => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            Err(GroupOperationError::Policy)
        }
        Err(GroupOperationError::Frozen) => Err(GroupOperationError::Frozen),
    }
}

/// Persists a pairwise-authenticated target acceptance before returning its
/// invitation disposition to the authority-side coordinator.
pub(crate) fn commit_group_invitation_acceptance<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    book: &mut InvitationBook,
    now: u64,
    input: GroupReceiveInput<'_>,
) -> Result<InvitationStatus, GroupOperationError> {
    let acceptance = match GroupPayload::decode(input.plaintext) {
        Ok(GroupPayload::InvitationAcceptance(acceptance)) => acceptance,
        _ => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            return Err(GroupOperationError::Policy);
        }
    };
    if acceptance.group_id != book.group_id() {
        commit_malformed_group_payload(
            store,
            snapshot,
            input.plaintext,
            input.provider_state,
            input.provider_effect,
        )?;
        return Err(GroupOperationError::Policy);
    }
    let authenticated_target = Member::new(
        input.authenticated_identity.to_vec(),
        vec![input.peer.device],
    );
    let result = commit_group_invitation_transition_with_provider(
        store,
        snapshot,
        book,
        Some((input.provider_state.clone(), input.provider_effect)),
        |candidate| {
            candidate
                .accept(
                    acceptance.invitation_id,
                    &authenticated_target,
                    acceptance.source_revision,
                    &acceptance.source_roster_digest,
                    now,
                )
                .map(|record| record.status)
        },
    );
    match result {
        Ok(status) => Ok(status),
        Err(GroupOperationError::Policy) => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            Err(GroupOperationError::Policy)
        }
        Err(GroupOperationError::Frozen) => Err(GroupOperationError::Frozen),
    }
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

/// Produces one recipient's exact group ciphertext with the live provider,
/// then commits it and the exported provider state to the outbox. A provider
/// failure after encryption is frozen rather than retried with new bytes.
pub(crate) async fn prepare_outbox_group_recipient<P, S>(
    client: &mut Client<P>,
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    id: &LogicalMessageId,
    recipient: &Member,
    route: &tacenta_relay::DeviceAddr,
) -> Result<RecipientProgress, GroupLiveError>
where
    P: tacenta_core::crypto::CryptoProvider,
    S: OperationStore,
{
    let application = outbox
        .send(id)
        .map_err(|_| GroupLiveError::Policy)?
        .application_context(recipient)
        .map_err(|_| GroupLiveError::Policy)?;
    let payload = GroupPayload::Application(application)
        .encode()
        .map_err(|_| GroupLiveError::Policy)?;
    let (ciphertext, provider_state) = client
        .prepare_group_ciphertext(route, recipient.identity(), &payload)
        .await
        .map_err(|error| live_client_error(error.kind()))?;
    commit_outbox_prepared_ciphertext(
        store,
        snapshot,
        outbox,
        id,
        recipient,
        ciphertext,
        provider_state,
    )
    .map_err(Into::into)
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

/// Dispatches the exact ciphertext from an already committed handoff and only
/// then records the relay observation. A transport error leaves the outbox in
/// its prior handed-off state for an exact-byte retry.
pub(crate) async fn dispatch_outbox_group_handoff<P, S>(
    client: &mut Client<P>,
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    id: &LogicalMessageId,
    recipient: &Member,
    route: &tacenta_relay::DeviceAddr,
) -> Result<RecipientProgress, GroupLiveError>
where
    P: tacenta_core::crypto::CryptoProvider,
    S: OperationStore,
{
    let handoff = commit_outbox_handoff_reservation(store, snapshot, outbox, id, recipient)
        .map_err(GroupLiveError::from)?;
    let ciphertext = handoff
        .ciphertext
        .as_deref()
        .ok_or(GroupLiveError::Policy)?;
    client
        .dispatch_group_ciphertext(route, ciphertext)
        .await
        .map_err(|error| live_client_error(error.kind()))?;
    commit_outbox_relay_acceptance(store, snapshot, outbox, id, recipient).map_err(Into::into)
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
    candidate_snapshot.application_state = candidate_receiver
        .encode_state()
        .map_err(|_| GroupOperationError::Policy)?;
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
    let context = match GroupPayload::decode(input.plaintext) {
        Ok(GroupPayload::Application(context)) => context,
        Ok(GroupPayload::Roster(_))
        | Ok(GroupPayload::InvitationBootstrap(_))
        | Ok(GroupPayload::InvitationAcceptance(_))
        | Err(_) => {
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

/// Parses the authenticated canonical inner payload once and commits exactly
/// the state machine selected by its tag. Callers pass only payloads decrypted
/// from a relay envelope already classified as [`MessageKind::Group`].
pub(crate) fn commit_group_payload<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    view: &mut RosterView,
    receiver: &mut GroupReceiver,
    logical_sends: &mut [LogicalSend],
    input: GroupReceiveInput<'_>,
) -> Result<GroupPayloadDisposition, GroupOperationError> {
    let payload = match GroupPayload::decode(input.plaintext) {
        Ok(payload) => payload,
        Err(_) => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            return Ok(GroupPayloadDisposition::Application(
                ReceiveDisposition::Rejected(ReceiveRefusal::Malformed),
            ));
        }
    };
    let authenticated_peer = Member::new(
        input.authenticated_identity.to_vec(),
        vec![input.peer.device],
    );
    match payload {
        GroupPayload::Application(context) => commit_receive_disposition(
            store,
            snapshot,
            receiver,
            &context,
            &authenticated_peer,
            input.provider_state,
            input.provider_effect,
        )
        .map(GroupPayloadDisposition::Application),
        GroupPayload::Roster(candidate) => commit_roster_transition(
            store,
            snapshot,
            RosterCommitState {
                view,
                receiver: Some(receiver),
                provider: Some((input.provider_state, input.provider_effect)),
                control_outbox: None,
                prepared_control: None,
                invitation_book: None,
                admission: None,
            },
            &authenticated_peer,
            candidate,
            logical_sends,
        )
        .map(GroupPayloadDisposition::Roster),
        GroupPayload::InvitationBootstrap(_) | GroupPayload::InvitationAcceptance(_) => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            Ok(GroupPayloadDisposition::Application(
                ReceiveDisposition::Rejected(ReceiveRefusal::Malformed),
            ))
        }
    }
}

/// Binds pairwise-authenticated provider identity and device data to the
/// pinned authority, then commits a roster-control payload with the provider
/// transition that authenticated it. Application payloads are not controls.
pub(crate) fn commit_group_roster_plaintext<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    view: &mut RosterView,
    receiver: &mut GroupReceiver,
    logical_sends: &mut [LogicalSend],
    input: GroupReceiveInput<'_>,
) -> Result<RosterCommit, GroupOperationError> {
    let candidate = match GroupPayload::decode(input.plaintext) {
        Ok(GroupPayload::Roster(candidate)) => candidate,
        Ok(GroupPayload::Application(_))
        | Ok(GroupPayload::InvitationBootstrap(_))
        | Ok(GroupPayload::InvitationAcceptance(_))
        | Err(_) => {
            commit_malformed_group_payload(
                store,
                snapshot,
                input.plaintext,
                input.provider_state,
                input.provider_effect,
            )?;
            return Err(GroupOperationError::Policy);
        }
    };
    let authenticated_authority = Member::new(
        input.authenticated_identity.to_vec(),
        vec![input.peer.device],
    );
    commit_roster_transition(
        store,
        snapshot,
        RosterCommitState {
            view,
            receiver: Some(receiver),
            provider: Some((input.provider_state, input.provider_effect)),
            control_outbox: None,
            prepared_control: None,
            invitation_book: None,
            admission: None,
        },
        &authenticated_authority,
        candidate,
        logical_sends,
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
        RosterCommitState {
            view,
            receiver: None,
            provider: None,
            control_outbox: None,
            prepared_control: None,
            invitation_book: None,
            admission: None,
        },
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
        RosterCommitState {
            view,
            receiver: Some(receiver),
            provider: None,
            control_outbox: None,
            prepared_control: None,
            invitation_book: None,
            admission: None,
        },
        authenticated_authority,
        candidate,
        logical_sends,
    )
}

fn commit_roster_transition<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    state: RosterCommitState<'_>,
    authenticated_authority: &Member,
    candidate: Roster,
    logical_sends: &mut [LogicalSend],
) -> Result<RosterCommit, GroupOperationError> {
    let preimage = candidate
        .encode()
        .map_err(|_| GroupOperationError::Policy)?;
    let commitment = roster_commitment(&preimage);
    let mut candidate_view = state.view.clone();
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
    let mut control_records = vec![encode_roster_record(&preimage, &commitment, disposition)?];
    if let Some((provider_state, _)) = &state.provider {
        candidate_snapshot.provider_state = provider_state.clone();
    }
    let mut candidate_control_outbox = state.control_outbox.as_deref().cloned();
    if let Some(prepared) = &state.prepared_control {
        if disposition != RosterDisposition::Accepted {
            return Err(GroupOperationError::Policy);
        }
        let outbox = candidate_control_outbox
            .as_mut()
            .ok_or(GroupOperationError::Policy)?;
        outbox
            .record_prepared(
                prepared.recipient.clone(),
                prepared.payload.clone(),
                prepared.ciphertext.clone(),
            )
            .map_err(|_| GroupOperationError::Policy)?;
        control_records.push(encode_control_outbox_record(
            &outbox
                .encode_state()
                .map_err(|_| GroupOperationError::Policy)?,
        )?);
    }
    let mut candidate_invitation_book = state.invitation_book.as_deref().cloned();
    if let Some(admission) = &state.admission {
        if disposition != RosterDisposition::Accepted
            || !candidate
                .members
                .iter()
                .any(|member| member == &admission.target)
        {
            return Err(GroupOperationError::Policy);
        }
        let book = candidate_invitation_book
            .as_mut()
            .ok_or(GroupOperationError::Policy)?;
        if !book
            .records()
            .iter()
            .any(|record| record.id == admission.id && record.target == admission.target)
        {
            return Err(GroupOperationError::Policy);
        }
        book.admit(
            admission.id,
            authenticated_authority,
            &candidate.authority,
            candidate.revision,
            admission.now,
        )
        .map_err(|_| GroupOperationError::Policy)?;
        control_records.push(encode_invitation_book_record(
            &book
                .encode_state()
                .map_err(|_| GroupOperationError::Policy)?,
        )?);
    }
    if let Some((_, provider_effect)) = state.provider {
        control_records.push(encode_control_effect_record(provider_effect));
    }
    control_records.push(encode_roster_view_record(
        &candidate_view
            .encode_state()
            .map_err(|_| GroupOperationError::Policy)?,
    )?);
    append_group_control_records(&mut candidate_snapshot, control_records);
    let mut candidate_receiver = state.receiver.as_deref().cloned();
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
    if let Some(receiver) = &candidate_receiver {
        candidate_snapshot.application_state = receiver
            .encode_state()
            .map_err(|_| GroupOperationError::Policy)?;
    }
    if store.commit(&candidate_snapshot) != CommitOutcome::Committed {
        return Err(GroupOperationError::Frozen);
    }
    *snapshot = candidate_snapshot;
    *state.view = candidate_view;
    logical_sends.clone_from_slice(&candidate_sends);
    if let (Some(receiver), Some(candidate_receiver)) = (state.receiver, candidate_receiver) {
        *receiver = candidate_receiver;
    }
    if let (Some(outbox), Some(candidate_outbox)) = (state.control_outbox, candidate_control_outbox)
    {
        *outbox = candidate_outbox;
    }
    if let (Some(book), Some(candidate_book)) = (state.invitation_book, candidate_invitation_book) {
        *book = candidate_book;
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

fn append_group_control_records(
    snapshot: &mut OperationSnapshot,
    records: impl IntoIterator<Item = Vec<u8>>,
) {
    snapshot.group_controls.extend(records);
    while snapshot.group_controls.len() > MAX_GROUP_CONTROL_RECORDS {
        let latest_roster_view = snapshot
            .group_controls
            .iter()
            .rposition(|record| record.starts_with(b"TCGV"));
        let latest_invitation_book = snapshot
            .group_controls
            .iter()
            .rposition(|record| record.starts_with(b"TCGB"));
        let latest_control_outbox = snapshot
            .group_controls
            .iter()
            .rposition(|record| record.starts_with(b"TCGO"));
        let eviction = snapshot
            .group_controls
            .iter()
            .enumerate()
            .find_map(|(index, _)| {
                (Some(index) != latest_roster_view
                    && Some(index) != latest_invitation_book
                    && Some(index) != latest_control_outbox)
                    .then_some(index)
            })
            .expect("the retained checkpoints fit inside the control record bound");
        snapshot.group_controls.remove(eviction);
    }
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

fn encode_control_effect_record(effect: CryptoStateEffect) -> Vec<u8> {
    let effect = match effect {
        CryptoStateEffect::Unchanged => 0,
        CryptoStateEffect::Advanced => 1,
        CryptoStateEffect::Terminal => 2,
    };
    vec![b'T', b'C', b'G', b'E', effect]
}

fn encode_roster_view_record(state: &[u8]) -> Result<Vec<u8>, GroupOperationError> {
    let length = u32::try_from(state.len()).map_err(|_| GroupOperationError::Policy)?;
    let mut record = Vec::with_capacity(8 + state.len());
    record.extend_from_slice(b"TCGV");
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(state);
    Ok(record)
}

fn encode_invitation_book_record(state: &[u8]) -> Result<Vec<u8>, GroupOperationError> {
    let length = u32::try_from(state.len()).map_err(|_| GroupOperationError::Policy)?;
    let mut record = Vec::with_capacity(8 + state.len());
    record.extend_from_slice(b"TCGB");
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(state);
    Ok(record)
}

fn decode_invitation_book_record(record: &[u8]) -> Result<&[u8], GroupOperationError> {
    if !record.starts_with(b"TCGB") {
        return Err(GroupOperationError::Policy);
    }
    let bytes = record.get(4..).ok_or(GroupOperationError::Policy)?;
    let (length, state) = bytes
        .split_at_checked(4)
        .ok_or(GroupOperationError::Policy)?;
    let length = usize::try_from(u32::from_be_bytes(
        length.try_into().map_err(|_| GroupOperationError::Policy)?,
    ))
    .map_err(|_| GroupOperationError::Policy)?;
    if state.len() != length {
        return Err(GroupOperationError::Policy);
    }
    Ok(state)
}

fn encode_control_outbox_record(state: &[u8]) -> Result<Vec<u8>, GroupOperationError> {
    let length = u32::try_from(state.len()).map_err(|_| GroupOperationError::Policy)?;
    let mut record = Vec::with_capacity(8 + state.len());
    record.extend_from_slice(b"TCGO");
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(state);
    Ok(record)
}

fn decode_control_outbox_record(record: &[u8]) -> Result<&[u8], GroupOperationError> {
    if !record.starts_with(b"TCGO") {
        return Err(GroupOperationError::Policy);
    }
    let bytes = record.get(4..).ok_or(GroupOperationError::Policy)?;
    let (length, state) = bytes
        .split_at_checked(4)
        .ok_or(GroupOperationError::Policy)?;
    let length = usize::try_from(u32::from_be_bytes(
        length.try_into().map_err(|_| GroupOperationError::Policy)?,
    ))
    .map_err(|_| GroupOperationError::Policy)?;
    if state.len() != length {
        return Err(GroupOperationError::Policy);
    }
    Ok(state)
}

fn decode_roster_view_record(record: &[u8]) -> Result<&[u8], GroupOperationError> {
    if !record.starts_with(b"TCGV") {
        return Err(GroupOperationError::Policy);
    }
    let bytes = record.get(4..).ok_or(GroupOperationError::Policy)?;
    let (length, state) = bytes
        .split_at_checked(4)
        .ok_or(GroupOperationError::Policy)?;
    let length = usize::try_from(u32::from_be_bytes(
        length.try_into().map_err(|_| GroupOperationError::Policy)?,
    ))
    .map_err(|_| GroupOperationError::Policy)?;
    if state.len() != length {
        return Err(GroupOperationError::Policy);
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::{
        ControlOutbox, GroupLiveError, GroupOperationError, GroupPayloadDisposition,
        GroupReceiveInput, InvitationAdmission, MAX_GROUP_CONTROL_RECORDS, PreparedControl,
        RosterCommit, RosterCommitState, bind_prepared_ciphertext,
        commit_group_control_outbox_transition, commit_group_invitation_acceptance,
        commit_group_invitation_bootstrap, commit_group_invitation_transition,
        commit_group_payload, commit_group_plaintext, commit_handoff_reservation,
        commit_logical_intent, commit_outbox_handoff_reservation,
        commit_outbox_prepared_ciphertext, commit_outbox_relay_acceptance,
        commit_prepared_ciphertext, commit_prepared_control_handoff, commit_receive_disposition,
        commit_roster_successor, commit_roster_successor_with_receiver, commit_roster_transition,
        live_client_error, recipient_can_receive_installed_roster_control,
        recipient_can_receive_roster_control, recover_group_control_outbox,
        recover_group_invitation_book, recover_group_outbox, recover_group_receiver,
        recover_group_roster_view,
    };
    use crate::ErrorKind;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::operation_store::FileOperationStore;
    use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};
    use tacenta_core::crypto::{Address, CryptoStateEffect, groups::roster_commitment};
    use tacenta_group::{
        ApplicationContext, DIGEST_LEN, GroupId, GroupOutbox, GroupPayload, GroupReceiver,
        Invitation, InvitationAcceptance, InvitationBook, InvitationBootstrap, InvitationId,
        InvitationStatus, LogicalSend, Member, OutboxDisposition, POLICY_VERSION_V1,
        ReceiveDisposition, ReceiveRefusal, RecipientDisposition, Roster, RosterDisposition,
        RosterView,
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
    fn only_transient_live_client_errors_leave_a_group_handoff_retryable() {
        assert_eq!(
            live_client_error(ErrorKind::Network),
            GroupLiveError::Transport
        );
        assert_eq!(
            live_client_error(ErrorKind::RateLimited),
            GroupLiveError::Transport
        );
        assert_eq!(
            live_client_error(ErrorKind::NotFound),
            GroupLiveError::Frozen
        );
        assert_eq!(
            live_client_error(ErrorKind::InvalidArgument),
            GroupLiveError::Frozen
        );
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
    fn core_bound_receiver_state_recovers_stable_group_delivery() {
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(9);
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
        let digest = roster_commitment(&roster.encode().unwrap());
        let mut receiver = GroupReceiver::new(roster, digest, bob());
        let context = ApplicationContext::new(
            GroupId::new(*b"bounded-group-id"),
            1,
            digest,
            alice(),
            bob(),
            3,
            b"hello".to_vec(),
        )
        .unwrap();
        assert_eq!(
            commit_receive_disposition(
                &mut store,
                &mut snapshot,
                &mut receiver,
                &context,
                &alice(),
                vec![4, 5, 6],
                CryptoStateEffect::Advanced,
            ),
            Ok(ReceiveDisposition::Accepted { event_id: 0 })
        );

        assert_eq!(recover_group_receiver(&snapshot), Ok(receiver));
    }

    #[test]
    fn core_bound_roster_checkpoint_recovers_the_latest_accepted_view() {
        let genesis = Roster::new(
            GroupId::new(*b"bounded-group-id"),
            0,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice()],
        )
        .unwrap();
        let genesis_digest = roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_digest).unwrap();
        let next = Roster::new(
            GroupId::new(*b"bounded-group-id"),
            1,
            genesis_digest,
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        commit_roster_successor(
            &mut store,
            &mut snapshot,
            &mut view,
            &alice(),
            next,
            &mut [],
        )
        .unwrap();

        assert_eq!(recover_group_roster_view(&snapshot, &alice()), Ok(view));
    }

    #[test]
    fn invitation_transition_commits_a_recoverable_book_before_returning() {
        let group_id = GroupId::new(*b"bounded-group-id");
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            group_id,
            bob(),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut book = InvitationBook::new(group_id);

        let disposition =
            commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |candidate| {
                candidate
                    .create(&alice(), &alice(), &[alice()], invitation, 0)
                    .map(|record| record.status)
            })
            .unwrap();

        assert_eq!(disposition, InvitationStatus::Pending);
        assert_eq!(&snapshot.group_controls[0][..4], b"TCGB");
        assert_eq!(recover_group_invitation_book(&snapshot, group_id), Ok(book));
    }

    #[test]
    fn invitation_bootstrap_and_acceptance_persist_authenticated_provider_state() {
        let group_id = GroupId::new(*b"bounded-group-id");
        let source = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let source_digest = roster_commitment(&source.encode().unwrap());
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            group_id,
            bob(),
            0,
            source_digest,
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        let bootstrap = InvitationBootstrap::new(invitation, source.clone()).unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut book = InvitationBook::new(group_id);

        assert_eq!(
            commit_group_invitation_bootstrap(
                &mut store,
                &mut snapshot,
                &mut book,
                &bob(),
                1,
                GroupReceiveInput {
                    plaintext: &GroupPayload::InvitationBootstrap(bootstrap.clone())
                        .encode()
                        .unwrap(),
                    authenticated_identity: alice().identity(),
                    peer: &Address::new("alice", 1),
                    provider_state: vec![4, 5],
                    provider_effect: CryptoStateEffect::Advanced,
                },
            ),
            Ok(bootstrap)
        );
        assert_eq!(snapshot.provider_state, vec![4, 5]);
        assert_eq!(book.records()[0].status, InvitationStatus::Pending);

        let acceptance =
            InvitationAcceptance::new(group_id, InvitationId::new([7; 16]), 0, source_digest)
                .unwrap();
        assert_eq!(
            commit_group_invitation_acceptance(
                &mut store,
                &mut snapshot,
                &mut book,
                2,
                GroupReceiveInput {
                    plaintext: &GroupPayload::InvitationAcceptance(acceptance)
                        .encode()
                        .unwrap(),
                    authenticated_identity: bob().identity(),
                    peer: &Address::new("bob", 1),
                    provider_state: vec![6, 7],
                    provider_effect: CryptoStateEffect::Advanced,
                },
            ),
            Ok(InvitationStatus::AcceptedPendingAdmission)
        );
        assert_eq!(snapshot.provider_state, vec![6, 7]);
        assert_eq!(recover_group_invitation_book(&snapshot, group_id), Ok(book));
    }

    #[test]
    fn unknown_invitation_checkpoint_does_not_expose_lifecycle_state() {
        let group_id = GroupId::new(*b"bounded-group-id");
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            group_id,
            bob(),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Unknown,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let before_snapshot = snapshot.clone();
        let mut book = InvitationBook::new(group_id);

        assert_eq!(
            commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |candidate| {
                candidate
                    .create(&alice(), &alice(), &[alice()], invitation, 0)
                    .map(|record| record.status)
            },),
            Err(GroupOperationError::Frozen)
        );
        assert!(book.records().is_empty());
        assert_eq!(snapshot, before_snapshot);
    }

    #[test]
    fn control_handoff_checkpoint_recovers_exact_ciphertext_after_reservation() {
        let payload = GroupPayload::Roster(roster(1, [0; DIGEST_LEN], vec![alice(), bob()]))
            .encode()
            .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = ControlOutbox::default();
        commit_group_control_outbox_transition(
            &mut store,
            &mut snapshot,
            &mut outbox,
            |candidate| candidate.record_prepared(bob(), payload.clone(), vec![7, 8]),
        )
        .unwrap();
        let reserved = commit_group_control_outbox_transition(
            &mut store,
            &mut snapshot,
            &mut outbox,
            |candidate| candidate.reserve(&bob(), &payload),
        )
        .unwrap();
        assert_eq!(reserved.ciphertext, vec![7, 8]);
        assert_eq!(recover_group_control_outbox(&snapshot), Ok(outbox));
    }

    #[test]
    fn prepared_control_commits_provider_state_with_exact_ciphertext() {
        let payload = GroupPayload::Roster(roster(1, [0; DIGEST_LEN], vec![alice(), bob()]))
            .encode()
            .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = ControlOutbox::default();
        let handoff = commit_prepared_control_handoff(
            &mut store,
            &mut snapshot,
            &mut outbox,
            bob(),
            payload,
            vec![7, 8],
            vec![4, 5, 6],
        )
        .unwrap();
        assert_eq!(handoff.ciphertext, vec![7, 8]);
        assert_eq!(snapshot.provider_state, vec![4, 5, 6]);
        assert_eq!(recover_group_control_outbox(&snapshot), Ok(outbox));
    }

    #[test]
    fn authority_roster_control_checkpoint_commits_local_roster_and_handoff_together() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment = roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_commitment).unwrap();
        let first = roster(1, *view.digest(), vec![alice(), bob()]);
        let first_commitment = roster_commitment(&first.encode().unwrap());
        assert_eq!(
            view.accept_successor(&alice(), first.clone(), first_commitment),
            RosterDisposition::Accepted
        );
        let mut receiver = GroupReceiver::new(first, first_commitment, alice());
        let successor = roster(2, *view.digest(), vec![alice(), bob()]);
        let payload = GroupPayload::Roster(successor.clone()).encode().unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = ControlOutbox::default();

        let commit = commit_roster_transition(
            &mut store,
            &mut snapshot,
            RosterCommitState {
                view: &mut view,
                receiver: Some(&mut receiver),
                provider: Some((vec![4, 5, 6], CryptoStateEffect::Advanced)),
                control_outbox: Some(&mut outbox),
                prepared_control: Some(PreparedControl {
                    recipient: bob(),
                    payload: payload.clone(),
                    ciphertext: vec![7, 8, 9],
                }),
                invitation_book: None,
                admission: None,
            },
            &alice(),
            successor,
            &mut [],
        )
        .unwrap();

        assert_eq!(commit.disposition, RosterDisposition::Accepted);
        assert_eq!(snapshot.provider_state, vec![4, 5, 6]);
        assert_eq!(recover_group_roster_view(&snapshot, &alice()), Ok(view));
        assert_eq!(recover_group_receiver(&snapshot), Ok(receiver));
        assert_eq!(recover_group_control_outbox(&snapshot), Ok(outbox.clone()));
        assert_eq!(
            outbox.handoff(&bob(), &payload).unwrap().ciphertext,
            vec![7, 8, 9]
        );
    }

    #[test]
    fn authority_admission_commits_the_roster_handoff_and_invitation_together() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment = roster_commitment(&genesis.encode().unwrap());
        let mut view =
            RosterView::accept_genesis(&alice(), genesis.clone(), genesis_commitment).unwrap();
        let mut receiver = GroupReceiver::new(genesis, genesis_commitment, alice());
        let successor = roster(1, *view.digest(), vec![alice(), bob()]);
        let payload = GroupPayload::Roster(successor.clone()).encode().unwrap();
        let mut book = InvitationBook::new(successor.group_id);
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            successor.group_id,
            bob(),
            0,
            genesis_commitment,
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        book.create(&alice(), &alice(), &[alice()], invitation, 0)
            .unwrap();
        book.accept(
            InvitationId::new([7; 16]),
            &bob(),
            0,
            &genesis_commitment,
            1,
        )
        .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = ControlOutbox::default();

        let commit = commit_roster_transition(
            &mut store,
            &mut snapshot,
            RosterCommitState {
                view: &mut view,
                receiver: Some(&mut receiver),
                provider: Some((vec![4, 5, 6], CryptoStateEffect::Advanced)),
                control_outbox: Some(&mut outbox),
                prepared_control: Some(PreparedControl {
                    recipient: bob(),
                    payload,
                    ciphertext: vec![7, 8, 9],
                }),
                invitation_book: Some(&mut book),
                admission: Some(InvitationAdmission {
                    id: InvitationId::new([7; 16]),
                    target: bob(),
                    now: 2,
                }),
            },
            &alice(),
            successor,
            &mut [],
        )
        .unwrap();

        assert_eq!(commit.disposition, RosterDisposition::Accepted);
        assert_eq!(
            book.records()[0].status,
            InvitationStatus::Admitted { revision: 1 }
        );
        assert_eq!(
            recover_group_invitation_book(&snapshot, book.group_id()),
            Ok(book)
        );
    }

    #[test]
    fn unknown_authority_control_checkpoint_keeps_local_roster_and_handoff_unchanged() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment = roster_commitment(&genesis.encode().unwrap());
        let mut view =
            RosterView::accept_genesis(&alice(), genesis.clone(), genesis_commitment).unwrap();
        let mut receiver = GroupReceiver::new(genesis, genesis_commitment, alice());
        let successor = roster(1, *view.digest(), vec![alice(), bob()]);
        let payload = GroupPayload::Roster(successor.clone()).encode().unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Unknown,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut outbox = ControlOutbox::default();
        let before_view = view.clone();
        let before_receiver = receiver.clone();
        let before_snapshot = snapshot.clone();
        let before_outbox = outbox.clone();

        assert_eq!(
            commit_roster_transition(
                &mut store,
                &mut snapshot,
                RosterCommitState {
                    view: &mut view,
                    receiver: Some(&mut receiver),
                    provider: Some((vec![4, 5, 6], CryptoStateEffect::Advanced)),
                    control_outbox: Some(&mut outbox),
                    prepared_control: Some(PreparedControl {
                        recipient: bob(),
                        payload,
                        ciphertext: vec![7, 8, 9],
                    }),
                    invitation_book: None,
                    admission: None,
                },
                &alice(),
                successor,
                &mut [],
            ),
            Err(GroupOperationError::Frozen)
        );
        assert_eq!(view, before_view);
        assert_eq!(receiver, before_receiver);
        assert_eq!(snapshot, before_snapshot);
        assert_eq!(outbox, before_outbox);
    }

    #[test]
    fn roster_controls_are_only_prepared_for_current_or_successor_members() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment = roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_commitment).unwrap();
        let admission = roster(1, *view.digest(), vec![alice(), bob()]);
        let admission_commitment = roster_commitment(&admission.encode().unwrap());

        assert!(recipient_can_receive_roster_control(
            &view,
            &admission,
            &bob()
        ));
        let stranger = Member::new(b"stranger-key".to_vec(), vec![1]);
        assert!(!recipient_can_receive_roster_control(
            &view, &admission, &stranger
        ));

        assert_eq!(
            view.accept_successor(&alice(), admission, admission_commitment),
            RosterDisposition::Accepted
        );
        let removal = roster(2, *view.digest(), vec![alice()]);
        assert!(recipient_can_receive_roster_control(
            &view,
            &removal,
            &bob()
        ));
        assert!(!recipient_can_receive_roster_control(
            &view, &removal, &stranger
        ));
        assert!(recipient_can_receive_installed_roster_control(
            &view,
            &alice(),
            &bob()
        ));
        assert!(!recipient_can_receive_installed_roster_control(
            &view,
            &alice(),
            &stranger
        ));
    }

    #[test]
    fn control_transcript_evicts_old_checkpoints_without_losing_the_latest_book() {
        let group_id = GroupId::new(*b"bounded-group-id");
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            group_id,
            bob(),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut book = InvitationBook::new(group_id);

        for _ in 0..=MAX_GROUP_CONTROL_RECORDS {
            commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |candidate| {
                candidate
                    .create(&alice(), &alice(), &[alice()], invitation.clone(), 0)
                    .map(|record| record.status)
            })
            .unwrap();
        }

        assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
        assert_eq!(recover_group_invitation_book(&snapshot, group_id), Ok(book));
    }

    #[test]
    fn roster_compaction_retains_an_older_invitation_checkpoint() {
        let group_id = GroupId::new(*b"bounded-group-id");
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            group_id,
            bob(),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(4);
        let mut book = InvitationBook::new(group_id);
        commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |candidate| {
            candidate
                .create(&alice(), &alice(), &[alice()], invitation, 0)
                .map(|record| record.status)
        })
        .unwrap();
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment = roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_commitment).unwrap();

        for revision in 1..=MAX_GROUP_CONTROL_RECORDS as u64 {
            let candidate = roster(revision, *view.digest(), vec![alice()]);
            commit_roster_successor(
                &mut store,
                &mut snapshot,
                &mut view,
                &alice(),
                candidate,
                &mut [],
            )
            .unwrap();
        }

        assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
        assert_eq!(recover_group_invitation_book(&snapshot, group_id), Ok(book));
        assert_eq!(recover_group_roster_view(&snapshot, &alice()), Ok(view));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_snapshot_restores_group_send_and_receive_state_together() {
        let path = std::env::temp_dir().join(format!(
            "tacenta-group-operation-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = FileOperationStore::new(&path);
        let mut snapshot = OperationSnapshot::empty(0);
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
        let digest = roster_commitment(&roster.encode().unwrap());
        let mut receiver = GroupReceiver::new(roster, digest, bob());
        let context = ApplicationContext::new(
            GroupId::new(*b"bounded-group-id"),
            1,
            digest,
            alice(),
            bob(),
            3,
            b"hello".to_vec(),
        )
        .unwrap();
        commit_receive_disposition(
            &mut store,
            &mut snapshot,
            &mut receiver,
            &context,
            &alice(),
            vec![4, 5, 6],
            CryptoStateEffect::Advanced,
        )
        .unwrap();

        let group_id = GroupId::new(*b"bounded-group-id");
        let mut invitations = InvitationBook::new(group_id);
        let invitation = Invitation::new(
            InvitationId::new([7; 16]),
            group_id,
            bob(),
            1,
            digest,
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        commit_group_invitation_transition(
            &mut store,
            &mut snapshot,
            &mut invitations,
            |candidate| {
                candidate
                    .create(&alice(), &alice(), &[alice()], invitation, 0)
                    .map(|record| record.status)
            },
        )
        .unwrap();

        let recovered_snapshot = store.recover().unwrap().unwrap();
        assert_eq!(recovered_snapshot, snapshot);
        assert_eq!(
            recover_group_outbox(&recovered_snapshot, GroupId::new(*b"bounded-group-id")),
            Ok(outbox)
        );
        assert_eq!(recover_group_receiver(&recovered_snapshot), Ok(receiver));
        assert_eq!(
            recover_group_invitation_book(&recovered_snapshot, group_id),
            Ok(invitations)
        );
        let _ = std::fs::remove_file(path);
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
                    plaintext: &GroupPayload::Application(receive_context())
                        .encode()
                        .unwrap(),
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

    #[test]
    fn canonical_group_payload_routes_roster_to_a_provider_bound_commit() {
        let genesis = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let genesis_commitment = roster_commitment(&genesis.encode().unwrap());
        let mut view = RosterView::accept_genesis(&alice(), genesis, genesis_commitment).unwrap();
        let r1 = roster(1, *view.digest(), vec![alice(), bob()]);
        let r1_commitment = roster_commitment(&r1.encode().unwrap());
        assert_eq!(
            view.accept_successor(&alice(), r1.clone(), r1_commitment),
            RosterDisposition::Accepted
        );
        let mut receiver = GroupReceiver::new(r1, r1_commitment, bob());
        let candidate = roster(2, *view.digest(), vec![alice(), bob()]);
        let mut store = Store {
            outcome: CommitOutcome::Committed,
            committed: None,
        };
        let mut snapshot = OperationSnapshot::empty(1);
        let mut sends = Vec::new();

        let payload = GroupPayload::Roster(candidate).encode().unwrap();
        let result = commit_group_payload(
            &mut store,
            &mut snapshot,
            &mut view,
            &mut receiver,
            &mut sends,
            GroupReceiveInput {
                plaintext: &payload,
                authenticated_identity: b"alice-key",
                peer: &Address::new("alice", 1),
                provider_state: vec![4, 5, 6],
                provider_effect: CryptoStateEffect::Advanced,
            },
        )
        .unwrap();

        assert_eq!(
            result,
            GroupPayloadDisposition::Roster(RosterCommit {
                disposition: RosterDisposition::Accepted,
                revalidated: Vec::new(),
            })
        );
        assert_eq!(snapshot.provider_state, vec![4, 5, 6]);
        assert!(
            snapshot
                .group_controls
                .iter()
                .any(|record| record.as_slice() == b"TCGE\x01")
        );
        assert_eq!(store.recover().unwrap(), Some(snapshot));
    }
}
