//! The experimental bounded group coordinator (decisions 0127, 0128, 0130).
//!
//! **Experimental.** This is the profile of the bounded group experiment: at
//! most eight members, one device each, one authority, one group per client.
//! Nothing here is in the SDK surface manifest or exported by a binding, and
//! its shape may change until a production profile is decided.
//!
//! A [`GroupClient`] takes a connected [`Client`] by value together with an
//! [`OperationStore`]. While it lives it is the only owner of the client's
//! mailbox and pairwise state, which is what makes three things true that the
//! plain `Client` cannot promise:
//!
//! - **Receive is staged.** [`receive`](GroupClient::receive) decrypts each item
//!   with the provider's outcome, commits its disposition and the provider
//!   state together, and only then acknowledges the committed prefix (0127).
//!   The authenticated peer and the state effect come from the provider.
//! - **One durable root.** Every pairwise operation, direct messages included,
//!   commits the exported provider state before it has an external effect
//!   (0128). A restart from the snapshot cannot rewind the ratchet.
//! - **A latch.** A write that did not commit freezes the coordinator until
//!   [`recover`](GroupClient::recover) reloads the durable snapshot and resets
//!   the client's provider state to it (0130).
//!
//! The bytes of every record here are product-owned and have no vectors yet;
//! see the review's CR-12.

use tacenta_core::crypto::{
    CryptoProvider, CryptoStateEffect, DefaultProvider, groups::roster_commitment,
};
use tacenta_group::{
    ApplicationContext, DIGEST_LEN, GroupId, GroupOutbox, GroupPayload, GroupReceiver, Invitation,
    InvitationAcceptance, InvitationBook, InvitationBootstrap, InvitationId, InvitationStatus,
    LogicalMessageId, LogicalSend, Member, POLICY_VERSION_V1, ReceiveDisposition, ReceiveRefusal,
    RecipientProgress, Roster, RosterDisposition, RosterView,
};
use tacenta_relay::DeviceAddr;

#[cfg(not(target_arch = "wasm32"))]
pub use crate::operation_store::FileOperationStore;
pub use crate::operation_store::{
    CommitOutcome, DurableStore, OperationSnapshot, OperationStore, StoreError,
};

use crate::group_control_outbox::Outbox as ControlOutbox;
use crate::group_operations::{
    AuthorityControlState, AuthorityInvitationState, GroupLiveError, GroupOperationError,
    GroupPayloadDisposition, GroupReceiveInput, InstalledControlState, InvitationAdmission,
    commit_group_invitation_acceptance, commit_group_invitation_bootstrap,
    commit_group_invitation_revocation, commit_group_invitation_transition,
    commit_group_payload_with_outbox, commit_logical_intent, commit_malformed_group_payload,
    commit_provider_state, dispatch_outbound_roster_control, dispatch_outbox_group_handoff,
    prepare_authority_invitation_revocation, prepare_authority_roster_control,
    prepare_installed_roster_control, prepare_outbound_invitation_control,
    prepare_outbox_group_recipient, recover_group_control_outbox, recover_group_invitation_book,
    recover_group_outbox, recover_group_receiver, recover_group_roster_view,
};
use crate::{Client, Error, MailSignal, MessageKind, Received};

/// What a coordinator call can refuse with.
#[derive(Debug)]
#[non_exhaustive]
pub enum GroupError {
    /// The underlying client failed (transport, provider, directory).
    Client(Error),
    /// A write did not commit, or an operation failed after it had consumed
    /// pairwise state. Nothing was published or sent after that point. Call
    /// [`recover`](GroupClient::recover) before anything else (0130).
    Frozen,
    /// The call was refused by policy before any pairwise operation: nothing
    /// durable changed.
    Policy,
    /// A transient transport or relay refusal. The exact committed bytes stay
    /// available for a retry.
    Transport,
    /// No group has been created, joined or awaited on this coordinator.
    NoGroup,
    /// The store could not be read, or its snapshot does not fit this client.
    Recovery,
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Client(error) => write!(f, "client error: {error}"),
            GroupError::Frozen => write!(f, "the group coordinator is frozen; recover first"),
            GroupError::Policy => write!(f, "refused by group policy"),
            GroupError::Transport => write!(f, "transient transport or relay refusal"),
            GroupError::NoGroup => write!(f, "no group is attached to this coordinator"),
            GroupError::Recovery => write!(f, "the operation store could not be recovered"),
        }
    }
}

impl std::error::Error for GroupError {}

impl From<Error> for GroupError {
    fn from(error: Error) -> Self {
        GroupError::Client(error)
    }
}

impl From<GroupOperationError> for GroupError {
    fn from(error: GroupOperationError) -> Self {
        match error {
            GroupOperationError::Policy => GroupError::Policy,
            GroupOperationError::Frozen => GroupError::Frozen,
        }
    }
}

impl From<GroupLiveError> for GroupError {
    fn from(error: GroupLiveError) -> Self {
        match error {
            GroupLiveError::Policy => GroupError::Policy,
            GroupLiveError::Frozen => GroupError::Frozen,
            GroupLiveError::Transport => GroupError::Transport,
        }
    }
}

/// The provider state a client must be connected from before it is handed to
/// [`GroupClient::open`]: the state in the store's newest durable snapshot, or
/// `None` for a store that has never held one.
pub fn recovered_provider_state(
    store: &mut impl OperationStore,
) -> Result<Option<Vec<u8>>, GroupError> {
    Ok(store
        .recover()
        .map_err(|_| GroupError::Recovery)?
        .map(|snapshot| snapshot.provider_state))
}

/// A newly accepted application message: committed, with its stable event ID,
/// before it was returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEvent {
    pub event_id: u64,
    pub group_id: GroupId,
    pub revision: u64,
    pub sender: Member,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl GroupEvent {
    fn new(event_id: u64, context: &ApplicationContext) -> Self {
        Self {
            event_id,
            group_id: context.group_id,
            revision: context.revision,
            sender: context.sender.clone(),
            sequence: context.logical_sequence,
            payload: context.payload.clone(),
        }
    }
}

/// What one group-class item did, as committed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupOutcome {
    /// A new application message.
    Event(GroupEvent),
    /// The same authenticated context again: no second event.
    Duplicate { event_id: u64 },
    /// An immediately-future context held for revalidation (0102).
    Deferred,
    /// A terminal refusal; the provider state it consumed was committed.
    Rejected(ReceiveRefusal),
    /// A roster control and the events its acceptance unlocked.
    Roster {
        disposition: RosterDisposition,
        events: Vec<GroupEvent>,
    },
    /// An invitation bootstrap was recorded as pending.
    Invitation(InvitationBootstrap),
    /// An acceptance or revocation moved an invitation to this status.
    InvitationStatus(InvitationStatus),
    /// A payload that failed its own checks (malformed, wrong sender or
    /// authority, no such group). Its provider transition was committed and
    /// nothing else changed.
    Refused,
}

/// One group-class item and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupReceipt {
    pub from: DeviceAddr,
    pub outcome: GroupOutcome,
}

/// Everything one [`receive`](GroupClient::receive) call processed, committed
/// and acknowledged.
#[derive(Clone, Debug, Default)]
pub struct Inbound {
    /// The group-class items, in relay order.
    pub items: Vec<GroupReceipt>,
    /// Items of any other class, returned after their provider state was
    /// committed (0128). Delivery is at-most-once.
    pub direct: Vec<Received>,
    /// Items the provider refused without changing state; dropped, as the plain
    /// client drops them.
    pub dropped: usize,
    /// The batch stopped at an item that could not be committed. Everything
    /// above was committed and acknowledged; the coordinator is frozen and
    /// must [`recover`](GroupClient::recover). The item and those after it were
    /// not acknowledged.
    pub frozen: bool,
}

impl Inbound {
    /// The newly accepted application messages across every item, in order.
    pub fn events(&self) -> Vec<&GroupEvent> {
        let mut events = Vec::new();
        for receipt in &self.items {
            match &receipt.outcome {
                GroupOutcome::Event(event) => events.push(event),
                GroupOutcome::Roster {
                    events: unlocked, ..
                } => events.extend(unlocked),
                _ => {}
            }
        }
        events
    }
}

/// The result of [`send_group`](GroupClient::send_group): the logical send and
/// where each recipient stands.
#[derive(Clone, Debug)]
pub struct GroupSend {
    pub id: LogicalMessageId,
    pub recipients: Vec<RecipientProgress>,
}

/// The result of [`install_roster`](GroupClient::install_roster).
#[derive(Clone, Debug)]
pub struct Install {
    /// The local disposition of the successor.
    pub disposition: RosterDisposition,
    /// Recipients whose control the relay accepted (or whose final attempt it
    /// accepted).
    pub delivered: Vec<Member>,
    /// Recipients whose committed control has not been accepted yet; retry with
    /// [`dispatch_pending_controls`](GroupClient::dispatch_pending_controls).
    pub pending: Vec<Member>,
}

/// The invitation an authority admits with the roster that includes it.
#[derive(Clone, Debug)]
pub struct Admission {
    pub id: InvitationId,
    pub target: Member,
}

struct GroupState {
    group_id: GroupId,
    /// The pinned authority (0119); the invitation and control paths accept
    /// authority only from this member.
    authority: Member,
    /// The genesis the caller supplied, kept to rebuild the state on recovery.
    genesis: Option<Roster>,
    local: Member,
    view: Option<RosterView>,
    receiver: Option<GroupReceiver>,
    outbox: GroupOutbox,
    control: ControlOutbox,
    book: InvitationBook,
}

/// The coordinator. See the module documentation.
pub struct GroupClient<P: CryptoProvider = DefaultProvider> {
    client: Client<P>,
    store: DurableStore,
    snapshot: OperationSnapshot,
    group: Option<GroupState>,
    /// Set when an operation failed after it had consumed pairwise state and
    /// before that state was committed; cleared by `recover` (0130).
    poisoned: bool,
}

impl<P: CryptoProvider> GroupClient<P> {
    /// Takes ownership of `client` and `store`. The client must have been
    /// connected from [`recovered_provider_state`] when the store holds a
    /// snapshot (`connect_with_state`): its identity is checked against the
    /// snapshot's. A store that holds nothing gets its first snapshot here,
    /// carrying the client's provider state, so the durable root exists before
    /// the first operation (0128).
    pub async fn open(
        client: Client<P>,
        store: impl OperationStore + Send + 'static,
    ) -> Result<Self, GroupError> {
        let mut store = DurableStore::new(store);
        let snapshot = match store.recover().map_err(|_| GroupError::Recovery)? {
            Some(snapshot) => {
                if !snapshot.provider_state.is_empty()
                    && !client.state_has_this_identity(&snapshot.provider_state)
                {
                    return Err(GroupError::Recovery);
                }
                snapshot
            }
            None => {
                let mut snapshot = OperationSnapshot::empty(0);
                let state = client.export_state().await?;
                commit_provider_state(&mut store, &mut snapshot, state)?;
                snapshot
            }
        };
        Ok(Self {
            client,
            store,
            snapshot,
            group: None,
            poisoned: false,
        })
    }

    /// This coordinator's own address.
    pub fn address(&self) -> &DeviceAddr {
        self.client.address()
    }

    /// The signal a relay push pings (see [`Client::mail`]).
    pub fn mail(&self) -> MailSignal {
        self.client.mail()
    }

    /// The local member binding: the provider's identity key and the crypto
    /// device (0107).
    pub fn member(&self) -> Result<Member, GroupError> {
        let device = u8::try_from(self.client.me.device).map_err(|_| GroupError::Policy)?;
        Ok(Member::new(self.client.party.identity_key(), vec![device]))
    }

    /// The generation of the newest snapshot this coordinator published.
    pub fn generation(&self) -> u64 {
        self.snapshot.generation
    }

    /// Whether the coordinator is frozen (0130).
    pub fn is_frozen(&self) -> bool {
        self.poisoned || self.store.is_frozen()
    }

    /// The accepted roster, once a group is attached and has a view.
    pub fn roster(&self) -> Option<&Roster> {
        self.group
            .as_ref()
            .and_then(|state| state.view.as_ref())
            .map(RosterView::roster)
    }

    /// The digest of the accepted roster (the core's commitment), once a group
    /// is attached and has a view.
    pub fn roster_digest(&self) -> Option<[u8; DIGEST_LEN]> {
        self.group
            .as_ref()
            .and_then(|state| state.view.as_ref())
            .map(|view| *view.digest())
    }

    /// The successor of the accepted roster for `members`: revision plus one,
    /// the accepted digest as predecessor, the same authority and policy, open,
    /// with the members in canonical order. It is only a value; installing it
    /// is [`install_roster`](Self::install_roster).
    pub fn next_roster(&self, mut members: Vec<Member>) -> Result<Roster, GroupError> {
        let state = self.group.as_ref().ok_or(GroupError::NoGroup)?;
        let view = state.view.as_ref().ok_or(GroupError::Policy)?;
        members.sort_by(|left, right| {
            left.identity()
                .cmp(right.identity())
                .then_with(|| left.device().cmp(right.device()))
        });
        Roster::new(
            state.group_id,
            view.roster()
                .revision
                .checked_add(1)
                .ok_or(GroupError::Policy)?,
            *view.digest(),
            state.authority.clone(),
            POLICY_VERSION_V1,
            false,
            members,
        )
        .map_err(|_| GroupError::Policy)
    }

    /// The invitation records of the attached group.
    pub fn invitations(&self) -> &[Invitation] {
        self.group
            .as_ref()
            .map_or(&[], |state| state.book.records())
    }

    /// Starts a group with this member as its authority and sole member, at
    /// revision zero. Idempotent: state already in the snapshot is recovered.
    pub fn create_group(&mut self, group_id: GroupId) -> Result<(), GroupError> {
        let local = self.member()?;
        let genesis = Roster::new(
            group_id,
            0,
            [0; DIGEST_LEN],
            local.clone(),
            POLICY_VERSION_V1,
            false,
            vec![local.clone()],
        )
        .map_err(|_| GroupError::Policy)?;
        self.attach(group_id, local, Some(genesis))
    }

    /// Attaches a group whose genesis roster and authority the caller knows
    /// from the bootstrap channel (0092). A roster view and receiver
    /// already recovered from the snapshot win over the genesis.
    pub fn join_group(&mut self, genesis: Roster, authority: Member) -> Result<(), GroupError> {
        self.attach(genesis.group_id, authority, Some(genesis))
    }

    /// Attaches a group only by id and authority: enough to receive an
    /// invitation bootstrap (recorded in the invitation book), not to observe
    /// rosters. Call [`join_group`](Self::join_group) with the genesis to go on.
    pub fn await_group(&mut self, group_id: GroupId, authority: Member) -> Result<(), GroupError> {
        self.attach(group_id, authority, None)
    }

    /// Rebuilds the group state from the snapshot, which is the only durable
    /// truth: nothing is visible in memory before its commit.
    fn attach(
        &mut self,
        group_id: GroupId,
        authority: Member,
        genesis: Option<Roster>,
    ) -> Result<(), GroupError> {
        let local = self.member()?;
        let snapshot = &self.snapshot;
        let has = |tag: &[u8]| snapshot.group_controls.iter().any(|r| r.starts_with(tag));
        let view = if has(b"TCGV") {
            Some(
                recover_group_roster_view(snapshot, &authority)
                    .map_err(|_| GroupError::Recovery)?,
            )
        } else if let Some(genesis) = &genesis {
            if genesis.revision != 0 || genesis.group_id != group_id {
                return Err(GroupError::Policy);
            }
            let digest = roster_commitment(&genesis.encode().map_err(|_| GroupError::Policy)?);
            Some(
                RosterView::accept_genesis(&authority, genesis.clone(), digest)
                    .map_err(|_| GroupError::Policy)?,
            )
        } else {
            None
        };
        let receiver = match &view {
            None => None,
            Some(view) if snapshot.application_state.is_empty() => Some(GroupReceiver::new(
                view.roster().clone(),
                *view.digest(),
                local.clone(),
            )),
            Some(view) => match recover_group_receiver(snapshot) {
                Ok(receiver) => Some(receiver),
                // The group crate refuses to restore the receiver of a member
                // that a roster removed or closed (CR-06). Such a member
                // refuses every application context as `not_active` anyway, so
                // an inert receiver over the accepted roster stands in; its
                // dedup history is not restored.
                Err(_) if !view.is_active(&local) => Some(GroupReceiver::new(
                    view.roster().clone(),
                    *view.digest(),
                    local.clone(),
                )),
                Err(_) => return Err(GroupError::Recovery),
            },
        };
        let outbox = recover_group_outbox(snapshot, group_id).map_err(|_| GroupError::Recovery)?;
        let control = recover_group_control_outbox(snapshot).map_err(|_| GroupError::Recovery)?;
        let book = if has(b"TCGB") {
            recover_group_invitation_book(snapshot, group_id).map_err(|_| GroupError::Recovery)?
        } else {
            InvitationBook::new(group_id)
        };
        self.group = Some(GroupState {
            group_id,
            authority,
            genesis,
            local,
            view,
            receiver,
            outbox,
            control,
            book,
        });
        Ok(())
    }

    /// Reloads the durable snapshot, resets the client's provider state to it
    /// and rebuilds the group state, then lifts the latch (0130). Whatever a
    /// frozen operation held in memory is discarded; a ciphertext it produced
    /// was never recorded and never sent.
    pub async fn recover(&mut self) -> Result<(), GroupError> {
        let snapshot = self
            .store
            .recover()
            .map_err(|_| GroupError::Recovery)?
            .ok_or(GroupError::Recovery)?;
        self.client
            .restore_state_in_place(&snapshot.provider_state)
            .await?;
        self.snapshot = snapshot;
        self.poisoned = false;
        if let Some(state) = self.group.take() {
            self.attach(state.group_id, state.authority, state.genesis)?;
        }
        Ok(())
    }

    /// Sends a direct message. The pairwise state it advances is committed
    /// before the ciphertext is put on the wire, and nothing is sent if that
    /// commit does not succeed (0128).
    pub async fn send_direct(&mut self, to: &DeviceAddr, message: &[u8]) -> Result<(), GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let prepared = self
            .client
            .prepare_send_as(to, message, tacenta_wire::Kind::Dm)
            .await?;
        // The ratchet has advanced in memory. From here until the commit
        // succeeds the coordinator must not continue on this state.
        self.poisoned = true;
        let provider_state = self.client.export_state().await?;
        commit_provider_state(&mut self.store, &mut self.snapshot, provider_state)?;
        self.poisoned = false;
        self.client
            .dispatch_prepared_send(&prepared)
            .await
            .map_err(transport_or_client)
    }

    /// Fetches what the relay holds, commits every item's disposition, and
    /// acknowledges the committed prefix (0127). `now` is the explicit logical
    /// time invitations are evaluated at.
    pub async fn receive(&mut self, now: u64) -> Result<Inbound, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let fetched = match self.client.fetch_staged().await {
            Err(Error::Io(_)) => {
                self.client.reconnect_with_patience().await?;
                self.client.fetch_staged().await?
            }
            other => other?,
        };
        let mut inbound = Inbound::default();
        let mut processed = 0usize;
        let mut stopped = None;
        for message in &fetched.messages {
            match self.stage(message, now, &mut inbound).await {
                Ok(()) => processed += 1,
                Err(error) => {
                    stopped = Some(error);
                    break;
                }
            }
        }
        if processed > 0 {
            self.client
                .acknowledge_fetched(fetched.from, processed)
                .await?;
        }
        match stopped {
            Some(GroupError::Frozen) => inbound.frozen = true,
            Some(error) if processed == 0 => return Err(error),
            _ => {}
        }
        Ok(inbound)
    }

    /// Waits for the relay to signal mail and then receives it.
    pub async fn receive_next(&mut self, now: u64) -> Result<Inbound, GroupError> {
        loop {
            let inbound = self.receive(now).await?;
            if !(inbound.items.is_empty()
                && inbound.direct.is_empty()
                && inbound.dropped == 0
                && !inbound.frozen)
            {
                return Ok(inbound);
            }
            self.client.mail.notified().await;
        }
    }

    async fn stage(
        &mut self,
        message: &tacenta_relay::StoredMessage,
        now: u64,
        inbound: &mut Inbound,
    ) -> Result<(), GroupError> {
        let item = match self.client.open_staged(message).await {
            Ok(item) => item,
            Err(error) => {
                // The provider may have consumed state we could not export.
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let result = self.commit_item(item, now, inbound);
        if result.is_err() {
            // The item may have advanced the pairwise state in memory and the
            // commit that would record it did not happen: nothing continues on
            // this state until `recover` resets it (0130).
            self.poisoned = true;
        }
        result
    }

    fn commit_item(
        &mut self,
        item: crate::StagedItem,
        now: u64,
        inbound: &mut Inbound,
    ) -> Result<(), GroupError> {
        let crate::StagedItem {
            from,
            peer,
            kind,
            plaintext,
            authenticated_identity,
            effect,
            provider_state,
        } = item;
        let Some(plaintext) = plaintext else {
            // The provider refused the ciphertext. A terminal failure keeps its
            // state; an unchanged refusal has nothing to commit.
            if effect != CryptoStateEffect::Unchanged {
                commit_malformed_group_payload(
                    &mut self.store,
                    &mut self.snapshot,
                    &[],
                    provider_state,
                    effect,
                )?;
            }
            inbound.dropped += 1;
            return Ok(());
        };
        if kind != MessageKind::Group {
            commit_provider_state(&mut self.store, &mut self.snapshot, provider_state)?;
            inbound.direct.push(Received {
                from,
                plaintext,
                kind,
            });
            return Ok(());
        }
        // A group-class item decrypted without an authenticated peer is not
        // attributed to anyone: refuse it rather than trust the relay's label.
        let Some(identity) = authenticated_identity else {
            commit_malformed_group_payload(
                &mut self.store,
                &mut self.snapshot,
                &plaintext,
                provider_state,
                effect,
            )?;
            inbound.items.push(GroupReceipt {
                from,
                outcome: GroupOutcome::Refused,
            });
            return Ok(());
        };
        let input = GroupReceiveInput {
            plaintext: &plaintext,
            authenticated_identity: &identity,
            peer: &peer,
            provider_state,
            provider_effect: effect,
        };
        let outcome = self.route(input, now)?;
        inbound.items.push(GroupReceipt { from, outcome });
        Ok(())
    }

    /// Routes one authenticated group plaintext by its own payload tag; the
    /// envelope class only chose that this parser runs (0116).
    fn route(
        &mut self,
        input: GroupReceiveInput<'_>,
        now: u64,
    ) -> Result<GroupOutcome, GroupOperationError> {
        let Self {
            store,
            snapshot,
            group,
            ..
        } = self;
        let payload = match GroupPayload::decode(input.plaintext) {
            Ok(payload) => payload,
            Err(_) => return refuse(store, snapshot, input),
        };
        let Some(state) = group.as_mut() else {
            return refuse(store, snapshot, input);
        };
        let peer_member = Member::new(
            input.authenticated_identity.to_vec(),
            vec![input.peer.device],
        );
        match payload {
            GroupPayload::Application(context) => {
                let (Some(view), Some(receiver)) = (state.view.as_mut(), state.receiver.as_mut())
                else {
                    return refuse(store, snapshot, input);
                };
                match commit_group_payload_with_outbox(
                    store,
                    snapshot,
                    view,
                    receiver,
                    &mut [],
                    &mut state.outbox,
                    input,
                )? {
                    GroupPayloadDisposition::Application(disposition) => {
                        Ok(receive_outcome(disposition, &context))
                    }
                    GroupPayloadDisposition::Roster(_) => Err(GroupOperationError::Policy),
                }
            }
            GroupPayload::Roster(_) => {
                let (Some(view), Some(receiver)) = (state.view.as_mut(), state.receiver.as_mut())
                else {
                    return refuse(store, snapshot, input);
                };
                match commit_group_payload_with_outbox(
                    store,
                    snapshot,
                    view,
                    receiver,
                    &mut [],
                    &mut state.outbox,
                    input,
                )? {
                    GroupPayloadDisposition::Roster(commit) => {
                        let mut events = Vec::new();
                        for item in &commit.revalidated {
                            if let ReceiveDisposition::Accepted { event_id } = item.disposition {
                                events.push(GroupEvent::new(event_id, &item.context));
                            }
                        }
                        Ok(GroupOutcome::Roster {
                            disposition: commit.disposition,
                            events,
                        })
                    }
                    GroupPayloadDisposition::Application(_) => Err(GroupOperationError::Policy),
                }
            }
            GroupPayload::InvitationBootstrap(_) => {
                // Only the pinned authority may start an invitation.
                if peer_member != state.authority {
                    return refuse(store, snapshot, input);
                }
                match commit_group_invitation_bootstrap(
                    store,
                    snapshot,
                    &mut state.book,
                    &state.local,
                    now,
                    input,
                ) {
                    Ok(bootstrap) => Ok(GroupOutcome::Invitation(bootstrap)),
                    Err(GroupOperationError::Policy) => Ok(GroupOutcome::Refused),
                    Err(error) => Err(error),
                }
            }
            GroupPayload::InvitationAcceptance(_) => {
                match commit_group_invitation_acceptance(
                    store,
                    snapshot,
                    &mut state.book,
                    now,
                    input,
                ) {
                    Ok(status) => Ok(GroupOutcome::InvitationStatus(status)),
                    Err(GroupOperationError::Policy) => Ok(GroupOutcome::Refused),
                    Err(error) => Err(error),
                }
            }
            GroupPayload::InvitationRevocation(_) => {
                match commit_group_invitation_revocation(
                    store,
                    snapshot,
                    &mut state.book,
                    &state.local,
                    &state.authority,
                    now,
                    input,
                ) {
                    Ok(status) => Ok(GroupOutcome::InvitationStatus(status)),
                    Err(GroupOperationError::Policy) => Ok(GroupOutcome::Refused),
                    Err(error) => Err(error),
                }
            }
        }
    }

    /// Records one logical group message for `recipients` (the members it goes
    /// to, each with its relay route), then prepares and hands off each
    /// recipient's exact ciphertext. A recipient the relay could not take
    /// stays handed-off for [`dispatch_pending_group_sends`](Self::dispatch_pending_group_sends).
    pub async fn send_group(
        &mut self,
        recipients: &[(Member, DeviceAddr)],
        payload: Vec<u8>,
    ) -> Result<GroupSend, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        let view = state.view.as_ref().ok_or(GroupError::Policy)?;
        let mut routes = recipients.to_vec();
        routes.sort_by(|left, right| {
            left.0
                .identity()
                .cmp(right.0.identity())
                .then_with(|| left.0.device().cmp(right.0.device()))
        });
        let sequence = state
            .outbox
            .sends()
            .iter()
            .filter(|send| send.id.group_id == state.group_id && send.id.sender == state.local)
            .map(|send| send.id.sequence)
            .max()
            .map_or(0, |highest| highest.saturating_add(1));
        let send = LogicalSend::new(
            view.roster(),
            *view.digest(),
            state.local.clone(),
            sequence,
            routes.iter().map(|(member, _)| member.clone()).collect(),
            payload,
        )
        .map_err(|_| GroupError::Policy)?;
        let id = send.id.clone();
        commit_logical_intent(store, snapshot, &mut state.outbox, send)?;
        drive_send(client, store, snapshot, &mut state.outbox, &id, &routes).await?;
        let recipients = state
            .outbox
            .send(&id)
            .map_err(|_| GroupError::Policy)?
            .recipients()
            .to_vec();
        Ok(GroupSend { id, recipients })
    }

    /// Prepares and hands off whatever every retained logical send still owes
    /// its recipients, using exactly the committed bytes. Recipients without a
    /// route in `routes` are left alone. Returns the number of sends driven.
    pub async fn dispatch_pending_group_sends(
        &mut self,
        routes: &[(Member, DeviceAddr)],
    ) -> Result<usize, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        let pending: Vec<LogicalMessageId> = state
            .outbox
            .sends()
            .iter()
            .filter(|send| !send.is_terminal())
            .map(|send| send.id.clone())
            .collect();
        for id in &pending {
            drive_send(client, store, snapshot, &mut state.outbox, id, routes).await?;
        }
        Ok(pending.len())
    }

    /// The authority installs `successor` locally and sends it to `recipients`
    /// (members and unexpired invitees, each with a route). The local
    /// transition, the provider state and the first recipient's exact
    /// ciphertext commit in one snapshot; every further recipient is prepared
    /// on the installed roster (0124). A successor that is already installed
    /// is only fanned out. `admission` marks an invitation admitted in the
    /// same commit.
    pub async fn install_roster(
        &mut self,
        successor: Roster,
        recipients: &[(Member, DeviceAddr)],
        admission: Option<Admission>,
        now: u64,
    ) -> Result<Install, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        if state.authority != state.local {
            return Err(GroupError::Policy);
        }
        let (Some(view), Some(receiver)) = (state.view.as_mut(), state.receiver.as_mut()) else {
            return Err(GroupError::Policy);
        };
        let mut installed = view.roster() == &successor;
        let mut disposition = RosterDisposition::Duplicate;
        let mut delivered = Vec::new();
        let mut pending = Vec::new();
        let mut admission = admission.map(|admission| InvitationAdmission {
            id: admission.id,
            target: admission.target,
            now,
        });
        for (recipient, route) in recipients {
            let handoff = if installed {
                prepare_installed_roster_control(
                    client,
                    store,
                    snapshot,
                    InstalledControlState {
                        view,
                        outbox: &mut state.control,
                        invitation_book: Some(&state.book),
                        control_now: now,
                    },
                    &state.local,
                    (recipient, route),
                )
                .await
            } else {
                prepare_authority_roster_control(
                    client,
                    store,
                    snapshot,
                    AuthorityControlState {
                        view,
                        receiver,
                        logical_sends: &mut [],
                        group_outbox: Some(&mut state.outbox),
                        outbox: &mut state.control,
                        invitation_book: Some(&mut state.book),
                        admission: admission.take(),
                        control_now: now,
                    },
                    &state.local,
                    (recipient, route),
                    successor.clone(),
                )
                .await
                .map(|commit| {
                    installed = true;
                    disposition = commit.roster.disposition;
                    commit.handoff
                })
            };
            let handoff = match handoff {
                Ok(handoff) => handoff,
                Err(GroupLiveError::Frozen) => return Err(GroupError::Frozen),
                // Nothing was installed and nothing prepared: refuse the call.
                Err(error) if !installed => return Err(error.into()),
                Err(_) => {
                    pending.push(recipient.clone());
                    continue;
                }
            };
            match dispatch_outbound_roster_control(
                client,
                store,
                snapshot,
                &mut state.control,
                recipient,
                &handoff.payload,
                route,
            )
            .await
            {
                Ok(_) => delivered.push(recipient.clone()),
                Err(GroupLiveError::Frozen) => return Err(GroupError::Frozen),
                Err(_) => pending.push(recipient.clone()),
            }
        }
        Ok(Install {
            disposition,
            delivered,
            pending,
        })
    }

    /// Hands off every committed control that has not reached a terminal state,
    /// using exactly its committed ciphertext. Controls to recipients without a
    /// route in `routes` are left alone. Returns how many the relay accepted.
    pub async fn dispatch_pending_controls(
        &mut self,
        routes: &[(Member, DeviceAddr)],
    ) -> Result<usize, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        let mut accepted = 0;
        for handoff in state.control.pending() {
            let Some((_, route)) = routes
                .iter()
                .find(|(member, _)| *member == handoff.recipient)
            else {
                continue;
            };
            match dispatch_outbound_roster_control(
                client,
                store,
                snapshot,
                &mut state.control,
                &handoff.recipient,
                &handoff.payload,
                route,
            )
            .await
            {
                Ok(_) => accepted += 1,
                Err(GroupLiveError::Frozen) => return Err(GroupError::Frozen),
                Err(_) => {}
            }
        }
        Ok(accepted)
    }

    /// The authority invites `target` at the current accepted revision: the
    /// invitation is recorded first, then the bootstrap control is prepared and
    /// handed off (0125).
    pub async fn invite(
        &mut self,
        id: InvitationId,
        target: &Member,
        route: &DeviceAddr,
        expires_at: u64,
        now: u64,
    ) -> Result<InvitationBootstrap, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        if state.authority != state.local {
            return Err(GroupError::Policy);
        }
        let view = state.view.as_ref().ok_or(GroupError::Policy)?;
        let roster = view.roster().clone();
        let invitation = Invitation::new(
            id,
            state.group_id,
            target.clone(),
            roster.revision,
            *view.digest(),
            POLICY_VERSION_V1,
            expires_at,
        )
        .map_err(|_| GroupError::Policy)?;
        commit_group_invitation_transition(store, snapshot, &mut state.book, |book| {
            book.create(
                &state.local,
                &state.authority,
                &roster.members,
                invitation.clone(),
                now,
            )
            .map(|_| ())
        })?;
        let bootstrap =
            InvitationBootstrap::new(invitation, roster).map_err(|_| GroupError::Policy)?;
        let handoff = prepare_outbound_invitation_control(
            client,
            store,
            snapshot,
            &mut state.control,
            target,
            route,
            GroupPayload::InvitationBootstrap(bootstrap.clone()),
        )
        .await?;
        dispatch_outbound_roster_control(
            client,
            store,
            snapshot,
            &mut state.control,
            target,
            &handoff.payload,
            route,
        )
        .await?;
        Ok(bootstrap)
    }

    /// The invited member accepts a recorded invitation and sends its
    /// acceptance to the authority (0125). It becomes `accepted_pending_admission`
    /// locally first; it has no application membership until the authority
    /// admits it.
    pub async fn accept_invitation(
        &mut self,
        id: InvitationId,
        authority_route: &DeviceAddr,
        now: u64,
    ) -> Result<InvitationStatus, GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        let record = state
            .book
            .records()
            .iter()
            .find(|record| record.id == id)
            .cloned()
            .ok_or(GroupError::Policy)?;
        let status =
            commit_group_invitation_transition(store, snapshot, &mut state.book, |book| {
                book.accept(
                    id,
                    &state.local,
                    record.source_revision,
                    &record.source_roster_digest,
                    now,
                )
                .map(|accepted| accepted.status)
            })?;
        let acceptance = InvitationAcceptance::new(
            state.group_id,
            id,
            record.source_revision,
            record.source_roster_digest,
        )
        .map_err(|_| GroupError::Policy)?;
        let handoff = prepare_outbound_invitation_control(
            client,
            store,
            snapshot,
            &mut state.control,
            &state.authority,
            authority_route,
            GroupPayload::InvitationAcceptance(acceptance),
        )
        .await?;
        dispatch_outbound_roster_control(
            client,
            store,
            snapshot,
            &mut state.control,
            &state.authority,
            &handoff.payload,
            authority_route,
        )
        .await?;
        Ok(status)
    }

    /// The authority revokes an unadmitted invitation: the terminal state is
    /// recorded first, then the revocation control is prepared and handed off
    /// (0126).
    pub async fn revoke_invitation(
        &mut self,
        id: InvitationId,
        target_route: &DeviceAddr,
        now: u64,
    ) -> Result<(), GroupError> {
        if self.is_frozen() {
            return Err(GroupError::Frozen);
        }
        let Self {
            client,
            store,
            snapshot,
            group,
            ..
        } = self;
        let state = group.as_mut().ok_or(GroupError::NoGroup)?;
        if state.authority != state.local {
            return Err(GroupError::Policy);
        }
        let target = state
            .book
            .records()
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.target.clone())
            .ok_or(GroupError::Policy)?;
        let handoff = prepare_authority_invitation_revocation(
            client,
            store,
            snapshot,
            AuthorityInvitationState {
                book: &mut state.book,
                outbox: &mut state.control,
                now,
            },
            &state.local,
            (&target, target_route),
            id,
        )
        .await?;
        dispatch_outbound_roster_control(
            client,
            store,
            snapshot,
            &mut state.control,
            &target,
            &handoff.payload,
            target_route,
        )
        .await?;
        Ok(())
    }
}

/// Commits a refusal of a payload that failed its own checks: the provider
/// transition is kept, nothing else changes.
fn refuse<S: OperationStore>(
    store: &mut S,
    snapshot: &mut OperationSnapshot,
    input: GroupReceiveInput<'_>,
) -> Result<GroupOutcome, GroupOperationError> {
    commit_malformed_group_payload(
        store,
        snapshot,
        input.plaintext,
        input.provider_state,
        input.provider_effect,
    )?;
    Ok(GroupOutcome::Refused)
}

fn receive_outcome(disposition: ReceiveDisposition, context: &ApplicationContext) -> GroupOutcome {
    match disposition {
        ReceiveDisposition::Accepted { event_id } => {
            GroupOutcome::Event(GroupEvent::new(event_id, context))
        }
        ReceiveDisposition::Duplicate { event_id } => GroupOutcome::Duplicate { event_id },
        ReceiveDisposition::Deferred => GroupOutcome::Deferred,
        ReceiveDisposition::Rejected(refusal) => GroupOutcome::Rejected(refusal),
    }
}

/// A client error from a dispatch: transient network and backpressure errors
/// keep the exact bytes available; everything else is the caller's to see.
fn transport_or_client(error: Error) -> GroupError {
    match error.kind() {
        crate::ErrorKind::Network | crate::ErrorKind::RateLimited => GroupError::Transport,
        _ => GroupError::Client(error),
    }
}

/// Prepares and hands off every recipient of one committed logical send that
/// has a route. A refusal or a transient failure for one recipient leaves the
/// others going; only a freeze stops the batch.
async fn drive_send<P: CryptoProvider>(
    client: &mut Client<P>,
    store: &mut DurableStore,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    id: &LogicalMessageId,
    routes: &[(Member, DeviceAddr)],
) -> Result<(), GroupError> {
    let recipients: Vec<Member> = outbox
        .send(id)
        .map_err(|_| GroupError::Policy)?
        .recipients()
        .iter()
        .map(|progress| progress.recipient.clone())
        .collect();
    for recipient in recipients {
        let Some((_, route)) = routes.iter().find(|(member, _)| *member == recipient) else {
            continue;
        };
        match prepare_outbox_group_recipient(client, store, snapshot, outbox, id, &recipient, route)
            .await
        {
            Ok(_) => {}
            Err(GroupLiveError::Frozen) => return Err(GroupError::Frozen),
            Err(_) => continue,
        }
        // A refusal or a transient failure here leaves the exact committed
        // handoff for a later retry; only a freeze stops the batch.
        if let Err(GroupLiveError::Frozen) =
            dispatch_outbox_group_handoff(client, store, snapshot, outbox, id, &recipient, route)
                .await
        {
            return Err(GroupError::Frozen);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
