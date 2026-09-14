//! Canonical values for Tacenta's bounded group-chat experiment.
//!
//! This crate owns product policy bytes only.  It has no crypto, storage,
//! networking, or provider dependency: callers obtain an authenticated peer
//! from the crypto provider and use these values inside that plaintext.  A
//! future core commitment helper consumes the roster preimage produced here.

use core::fmt;
use std::collections::BTreeSet;

mod invitation;
mod receive;
mod roster_view;
mod send;

pub use invitation::{Invitation, InvitationBook, InvitationId, InvitationStatus};
pub use receive::{GroupReceiver, ReceiveDisposition, ReceiveRefusal, RevalidatedReceive};
pub use roster_view::{RosterDisposition, RosterRefusal, RosterView};
pub use send::{
    GroupOutbox, LogicalMessageId, LogicalSend, OutboxDisposition, RecipientDisposition,
    RecipientProgress,
};

/// The first bounded profile uses 16 opaque group-ID bytes.
pub const GROUP_ID_LEN: usize = 16;
/// Roster and context commitments in the first profile are 32 bytes.
pub const DIGEST_LEN: usize = 32;
/// The one-authority validation profile has no more than eight members.
pub const MAX_MEMBERS: usize = 8;
/// The initial group-application payload bound.
pub const MAX_PAYLOAD_LEN: usize = 1_024;
/// Maximum canonical identity bytes held by one bounded member binding.
pub const MAX_IDENTITY_LEN: usize = 256;
/// Maximum canonical device bytes held by one bounded member binding.
pub const MAX_DEVICE_LEN: usize = 64;
/// Maximum complete canonical bounded-roster preimage size.
pub const MAX_ROSTER_LEN: usize = 4_096;
/// Maximum complete canonical bounded-application-context size.
pub const MAX_APPLICATION_CONTEXT_LEN: usize = 2_048;
/// The bounded profile's maximum number of unfinished logical sends per group.
pub const MAX_LIVE_LOGICAL_SENDS: usize = 8;
/// Policy version selected by the bounded validation profile.
pub const POLICY_VERSION_V1: u32 = 1;
/// `u64::MAX` is reserved and never encodes a group revision.
pub const RESERVED_REVISION: u64 = u64::MAX;

const ROSTER_DOMAIN: &[u8] = b"Tacenta Group Roster v1";
const APPLICATION_DOMAIN: &[u8] = b"Tacenta Group Application v1";

/// A parsing or profile-bound violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    NonCanonical,
    UnsupportedPolicy,
    ReservedRevision,
    TooManyMembers,
    PayloadTooLarge,
    IdentityTooLarge,
    DeviceTooLarge,
    RosterTooLarge,
    ContextTooLarge,
    Unauthorized,
    Conflict,
    WrongTarget,
    StaleSource,
    Expired,
    Revoked,
    WrongDisposition,
    EmptyRecipients,
    NotMember,
    Closed,
    RetryExhausted,
    OutboxFull,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed bounded group value",
            Self::NonCanonical => "non-canonical bounded group value",
            Self::UnsupportedPolicy => "unsupported bounded group policy",
            Self::ReservedRevision => "reserved bounded group revision",
            Self::TooManyMembers => "too many bounded group members",
            Self::PayloadTooLarge => "bounded group payload is too large",
            Self::IdentityTooLarge => "bounded group identity is too large",
            Self::DeviceTooLarge => "bounded group device is too large",
            Self::RosterTooLarge => "bounded group roster is too large",
            Self::ContextTooLarge => "bounded group application context is too large",
            Self::Unauthorized => "unauthorized bounded group action",
            Self::Conflict => "conflicting bounded group record",
            Self::WrongTarget => "bounded group invitation targets another member",
            Self::StaleSource => "stale bounded group invitation source",
            Self::Expired => "expired bounded group invitation",
            Self::Revoked => "revoked bounded group invitation",
            Self::WrongDisposition => "invalid bounded group invitation disposition",
            Self::EmptyRecipients => "bounded group logical send has no recipients",
            Self::NotMember => "bounded group member is not active in the roster",
            Self::Closed => "bounded group is closed",
            Self::RetryExhausted => "bounded group retry budget is exhausted",
            Self::OutboxFull => "bounded group outbox is full",
        })
    }
}

impl std::error::Error for Error {}

/// A fixed-width opaque group identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GroupId([u8; GROUP_ID_LEN]);

impl GroupId {
    pub fn new(bytes: [u8; GROUP_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; GROUP_ID_LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for GroupId {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.try_into().map(Self).map_err(|_| Error::Malformed)
    }
}

/// A product-validated identity/device binding.
///
/// The caller supplies canonical identity and device encodings from its
/// identity layer.  This crate preserves them exactly and applies the group
/// rules that compare complete bindings and identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    identity: Vec<u8>,
    device: Vec<u8>,
}

impl Member {
    pub fn new(identity: Vec<u8>, device: Vec<u8>) -> Self {
        Self { identity, device }
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub fn device(&self) -> &[u8] {
        &self.device
    }

    fn sort_key(&self) -> Vec<u8> {
        [self.identity.as_slice(), self.device.as_slice()].concat()
    }

    pub(crate) fn canonical_sort_key(&self) -> Vec<u8> {
        self.sort_key()
    }

    fn validate(&self) -> Result<(), Error> {
        if self.identity.len() > MAX_IDENTITY_LEN {
            return Err(Error::IdentityTooLarge);
        }
        if self.device.len() > MAX_DEVICE_LEN {
            return Err(Error::DeviceTooLarge);
        }
        Ok(())
    }
}

/// The exact product-owned preimage for a bounded group roster commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    pub group_id: GroupId,
    pub revision: u64,
    pub predecessor_digest: [u8; DIGEST_LEN],
    pub authority: Member,
    pub policy_version: u32,
    pub closed: bool,
    pub members: Vec<Member>,
}

impl Roster {
    pub fn new(
        group_id: GroupId,
        revision: u64,
        predecessor_digest: [u8; DIGEST_LEN],
        authority: Member,
        policy_version: u32,
        closed: bool,
        members: Vec<Member>,
    ) -> Result<Self, Error> {
        let roster = Self {
            group_id,
            revision,
            predecessor_digest,
            authority,
            policy_version,
            closed,
            members,
        };
        roster.validate()?;
        Ok(roster)
    }

    /// Encodes the preimage whose digest is carried by later roster revisions.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(ROSTER_DOMAIN);
        put_lp(&mut out, self.group_id.as_bytes())?;
        out.extend_from_slice(&self.revision.to_be_bytes());
        put_lp(&mut out, &self.predecessor_digest)?;
        put_member(&mut out, &self.authority)?;
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        out.push(u8::from(self.closed));
        put_u32(&mut out, self.members.len())?;
        for member in &self.members {
            put_member(&mut out, member)?;
        }
        Ok(out)
    }

    /// Decodes only an exact, canonical version-one roster preimage.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ROSTER_LEN {
            return Err(Error::RosterTooLarge);
        }
        let mut input = bytes;
        take_exact(&mut input, ROSTER_DOMAIN)?;
        let group_id = GroupId::try_from(take_lp(&mut input)?.as_slice())?;
        let revision = take_u64(&mut input)?;
        let predecessor_digest = take_lp(&mut input)?;
        let predecessor_digest = predecessor_digest
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let authority = take_member(&mut input)?;
        let policy_version = take_u32(&mut input)?;
        let closed = match take_byte(&mut input)? {
            0 => false,
            1 => true,
            _ => return Err(Error::Malformed),
        };
        let count = usize::try_from(take_u32(&mut input)?).map_err(|_| Error::Malformed)?;
        if count > MAX_MEMBERS {
            return Err(Error::TooManyMembers);
        }
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(take_member(&mut input)?);
        }
        if !input.is_empty() {
            return Err(Error::Malformed);
        }
        Self::new(
            group_id,
            revision,
            predecessor_digest,
            authority,
            policy_version,
            closed,
            members,
        )
    }

    fn validate(&self) -> Result<(), Error> {
        if self.revision == RESERVED_REVISION {
            return Err(Error::ReservedRevision);
        }
        if self.policy_version != POLICY_VERSION_V1 {
            return Err(Error::UnsupportedPolicy);
        }
        if self.members.len() > MAX_MEMBERS {
            return Err(Error::TooManyMembers);
        }
        self.authority.validate()?;
        let mut previous: Option<&Member> = None;
        let mut identities = BTreeSet::new();
        for member in &self.members {
            member.validate()?;
            if let Some(previous) = previous
                && previous.sort_key() >= member.sort_key()
            {
                return Err(Error::NonCanonical);
            }
            if !identities.insert(member.identity.as_slice()) {
                return Err(Error::NonCanonical);
            }
            previous = Some(member);
        }
        if self.encoded_len() > MAX_ROSTER_LEN {
            return Err(Error::RosterTooLarge);
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        ROSTER_DOMAIN.len()
            + lp_len(GROUP_ID_LEN)
            + 8
            + lp_len(DIGEST_LEN)
            + member_len(&self.authority)
            + 4
            + 1
            + 4
            + self.members.iter().map(member_len).sum::<usize>()
    }
}

/// The authenticated plaintext context of one bounded application message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationContext {
    pub group_id: GroupId,
    pub revision: u64,
    pub roster_digest: [u8; DIGEST_LEN],
    pub sender: Member,
    pub recipient: Member,
    pub logical_sequence: u64,
    pub payload: Vec<u8>,
}

impl ApplicationContext {
    pub fn new(
        group_id: GroupId,
        revision: u64,
        roster_digest: [u8; DIGEST_LEN],
        sender: Member,
        recipient: Member,
        logical_sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let context = Self {
            group_id,
            revision,
            roster_digest,
            sender,
            recipient,
            logical_sequence,
            payload,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(APPLICATION_DOMAIN);
        put_lp(&mut out, self.group_id.as_bytes())?;
        out.extend_from_slice(&self.revision.to_be_bytes());
        put_lp(&mut out, &self.roster_digest)?;
        put_member(&mut out, &self.sender)?;
        put_member(&mut out, &self.recipient)?;
        out.extend_from_slice(&self.logical_sequence.to_be_bytes());
        put_lp(&mut out, &self.payload)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_APPLICATION_CONTEXT_LEN {
            return Err(Error::ContextTooLarge);
        }
        let mut input = bytes;
        take_exact(&mut input, APPLICATION_DOMAIN)?;
        let group_id = GroupId::try_from(take_lp(&mut input)?.as_slice())?;
        let revision = take_u64(&mut input)?;
        let roster_digest = take_lp(&mut input)?;
        let roster_digest = roster_digest.try_into().map_err(|_| Error::Malformed)?;
        let sender = take_member(&mut input)?;
        let recipient = take_member(&mut input)?;
        let logical_sequence = take_u64(&mut input)?;
        let payload = take_lp(&mut input)?;
        if !input.is_empty() {
            return Err(Error::Malformed);
        }
        Self::new(
            group_id,
            revision,
            roster_digest,
            sender,
            recipient,
            logical_sequence,
            payload,
        )
    }

    fn validate(&self) -> Result<(), Error> {
        if self.revision == RESERVED_REVISION {
            return Err(Error::ReservedRevision);
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        self.sender.validate()?;
        self.recipient.validate()?;
        if self.encoded_len() > MAX_APPLICATION_CONTEXT_LEN {
            return Err(Error::ContextTooLarge);
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        APPLICATION_DOMAIN.len()
            + lp_len(GROUP_ID_LEN)
            + 8
            + lp_len(DIGEST_LEN)
            + member_len(&self.sender)
            + member_len(&self.recipient)
            + 8
            + lp_len(self.payload.len())
    }
}

fn lp_len(value_len: usize) -> usize {
    4 + value_len
}

fn member_len(member: &Member) -> usize {
    lp_len(member.identity.len()) + lp_len(member.device.len())
}

fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    let value = u32::try_from(value).map_err(|_| Error::Malformed)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_lp(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    put_u32(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn put_member(out: &mut Vec<u8>, member: &Member) -> Result<(), Error> {
    put_lp(out, member.identity())?;
    put_lp(out, member.device())
}

fn take(count: usize, input: &mut &[u8]) -> Result<Vec<u8>, Error> {
    let Some((value, rest)) = input.split_at_checked(count) else {
        return Err(Error::Malformed);
    };
    *input = rest;
    Ok(value.to_vec())
}

fn take_exact(input: &mut &[u8], expected: &[u8]) -> Result<(), Error> {
    if take(expected.len(), input)?.as_slice() == expected {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

fn take_byte(input: &mut &[u8]) -> Result<u8, Error> {
    take(1, input)?.first().copied().ok_or(Error::Malformed)
}

fn take_u32(input: &mut &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        take(4, input)?.try_into().map_err(|_| Error::Malformed)?,
    ))
}

fn take_u64(input: &mut &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        take(8, input)?.try_into().map_err(|_| Error::Malformed)?,
    ))
}

fn take_lp(input: &mut &[u8]) -> Result<Vec<u8>, Error> {
    let count = usize::try_from(take_u32(input)?).map_err(|_| Error::Malformed)?;
    take(count, input)
}

fn take_member(input: &mut &[u8]) -> Result<Member, Error> {
    let member = Member::new(take_lp(input)?, take_lp(input)?);
    member.validate()?;
    Ok(member)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> GroupId {
        GroupId::new(*b"bounded-group-id")
    }

    fn alice() -> Member {
        Member::new(b"alice-key".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob-key".to_vec(), vec![1])
    }

    fn roster() -> Roster {
        Roster::new(
            group(),
            0,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap()
    }

    #[test]
    fn canonical_roster_round_trips_byte_for_byte() {
        let encoded = roster().encode().unwrap();
        assert_eq!(Roster::decode(&encoded), Ok(roster()));
        assert_eq!(Roster::decode(&encoded).unwrap().encode(), Ok(encoded));
    }

    #[test]
    fn roster_refuses_an_unsorted_or_second_device_identity() {
        let unsorted = Roster::new(
            group(),
            0,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![bob(), alice()],
        );
        assert_eq!(unsorted, Err(Error::NonCanonical));

        let second_device = Roster::new(
            group(),
            0,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), Member::new(b"alice-key".to_vec(), vec![2])],
        );
        assert_eq!(second_device, Err(Error::NonCanonical));

        // Full-tuple ordering can place a longer, distinct identity between
        // two bindings of the same identity.  Identity uniqueness must not
        // rely only on adjacent roster entries.
        let separated_second_device = Roster::new(
            group(),
            0,
            [0; DIGEST_LEN],
            Member::new(vec![b'a'], vec![0]),
            POLICY_VERSION_V1,
            false,
            vec![
                Member::new(vec![b'a'], vec![0]),
                Member::new(vec![b'a', 1], vec![0]),
                Member::new(vec![b'a'], vec![2]),
            ],
        );
        assert_eq!(separated_second_device, Err(Error::NonCanonical));
    }

    #[test]
    fn roster_accepts_same_device_number_for_different_identities() {
        assert_eq!(roster().members, vec![alice(), bob()]);
    }

    #[test]
    fn roster_refuses_a_reserved_revision_and_trailing_bytes() {
        assert_eq!(
            Roster::new(
                group(),
                RESERVED_REVISION,
                [0; DIGEST_LEN],
                alice(),
                POLICY_VERSION_V1,
                false,
                vec![alice()],
            ),
            Err(Error::ReservedRevision)
        );
        let mut encoded = roster().encode().unwrap();
        encoded.push(0);
        assert_eq!(Roster::decode(&encoded), Err(Error::Malformed));
    }

    #[test]
    fn application_context_round_trips_and_binds_every_field() {
        let context = ApplicationContext::new(
            group(),
            2,
            [7; DIGEST_LEN],
            alice(),
            bob(),
            9,
            b"hello".to_vec(),
        )
        .unwrap();
        let encoded = context.encode().unwrap();
        assert_eq!(ApplicationContext::decode(&encoded), Ok(context.clone()));

        let changed_payload = ApplicationContext::new(
            group(),
            2,
            [7; DIGEST_LEN],
            alice(),
            bob(),
            9,
            b"hellO".to_vec(),
        )
        .unwrap();
        assert_ne!(encoded, changed_payload.encode().unwrap());
    }

    #[test]
    fn application_context_refuses_bad_digest_and_oversized_payload() {
        let mut encoded =
            ApplicationContext::new(group(), 2, [7; DIGEST_LEN], alice(), bob(), 9, vec![])
                .unwrap()
                .encode()
                .unwrap();
        let digest_length_offset = APPLICATION_DOMAIN.len() + 4 + GROUP_ID_LEN + 8;
        encoded[digest_length_offset..digest_length_offset + 4]
            .copy_from_slice(&31_u32.to_be_bytes());
        assert_eq!(ApplicationContext::decode(&encoded), Err(Error::Malformed));

        assert_eq!(
            ApplicationContext::new(
                group(),
                2,
                [7; DIGEST_LEN],
                alice(),
                bob(),
                9,
                vec![0; MAX_PAYLOAD_LEN + 1],
            ),
            Err(Error::PayloadTooLarge)
        );
    }

    #[test]
    fn group_codecs_reject_oversized_identity_device_and_input_before_parsing() {
        let oversized_identity = Member::new(vec![0; MAX_IDENTITY_LEN + 1], vec![1]);
        assert_eq!(
            Roster::new(
                group(),
                0,
                [0; DIGEST_LEN],
                oversized_identity.clone(),
                POLICY_VERSION_V1,
                false,
                vec![oversized_identity],
            ),
            Err(Error::IdentityTooLarge)
        );
        let oversized_device = Member::new(b"alice-key".to_vec(), vec![1; MAX_DEVICE_LEN + 1]);
        assert_eq!(
            ApplicationContext::new(
                group(),
                0,
                [0; DIGEST_LEN],
                oversized_device.clone(),
                bob(),
                0,
                Vec::new(),
            ),
            Err(Error::DeviceTooLarge)
        );
        assert_eq!(
            Roster::decode(&vec![0; MAX_ROSTER_LEN + 1]),
            Err(Error::RosterTooLarge)
        );
        assert_eq!(
            ApplicationContext::decode(&vec![0; MAX_APPLICATION_CONTEXT_LEN + 1]),
            Err(Error::ContextTooLarge)
        );
    }
}
