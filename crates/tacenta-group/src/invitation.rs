//! Product policy for the bounded invitation lifecycle.

use crate::{DIGEST_LEN, Error, GroupId, Member, POLICY_VERSION_V1, RESERVED_REVISION};

const INVITATION_BOOK_STATE_DOMAIN: &[u8] = b"Tacenta Group Invitation Book State v1";
const MAX_INVITATION_RECORDS: usize = 32;

/// A fixed-width opaque invitation identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvitationId([u8; 16]);

impl InvitationId {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&[u8]> for InvitationId {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes.try_into().map(Self).map_err(|_| Error::Malformed)
    }
}

/// A committed invitation's only legal lifecycle states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationStatus {
    Pending,
    AcceptedPendingAdmission,
    Admitted { revision: u64 },
    Revoked,
    Expired,
}

fn status_code(status: InvitationStatus) -> (u8, Option<u64>) {
    match status {
        InvitationStatus::Pending => (0, None),
        InvitationStatus::AcceptedPendingAdmission => (1, None),
        InvitationStatus::Admitted { revision } => (2, Some(revision)),
        InvitationStatus::Revoked => (3, None),
        InvitationStatus::Expired => (4, None),
    }
}

/// The immutable part of an authority-issued invitation and its disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitation {
    pub id: InvitationId,
    pub group_id: GroupId,
    pub target: Member,
    pub source_revision: u64,
    pub source_roster_digest: [u8; DIGEST_LEN],
    pub policy_version: u32,
    pub expires_at: u64,
    pub status: InvitationStatus,
}

impl Invitation {
    pub fn new(
        id: InvitationId,
        group_id: GroupId,
        target: Member,
        source_revision: u64,
        source_roster_digest: [u8; DIGEST_LEN],
        policy_version: u32,
        expires_at: u64,
    ) -> Result<Self, Error> {
        if source_revision == RESERVED_REVISION {
            return Err(Error::ReservedRevision);
        }
        if policy_version != POLICY_VERSION_V1 {
            return Err(Error::UnsupportedPolicy);
        }
        target.validate()?;
        Ok(Self {
            id,
            group_id,
            target,
            source_revision,
            source_roster_digest,
            policy_version,
            expires_at,
            status: InvitationStatus::Pending,
        })
    }

    fn same_immutable_fields(&self, candidate: &Self) -> bool {
        self.id == candidate.id
            && self.group_id == candidate.group_id
            && self.target == candidate.target
            && self.source_revision == candidate.source_revision
            && self.source_roster_digest == candidate.source_roster_digest
            && self.policy_version == candidate.policy_version
            && self.expires_at == candidate.expires_at
    }

    fn source_matches(&self, revision: u64, digest: &[u8; DIGEST_LEN]) -> bool {
        self.source_revision == revision && &self.source_roster_digest == digest
    }

    fn expire_if_due(&mut self, now: u64) {
        if now >= self.expires_at
            && matches!(
                self.status,
                InvitationStatus::Pending | InvitationStatus::AcceptedPendingAdmission
            )
        {
            self.status = InvitationStatus::Expired;
        }
    }
}

/// The authority and recipient-side invitation records for one group.
///
/// Authentication is supplied by the integration layer as the actual peer
/// binding of the pairwise channel.  These methods compare that binding with
/// the authority or target stored in the invitation; a relay address never
/// acts as identity evidence here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationBook {
    group_id: GroupId,
    invitations: Vec<Invitation>,
}

impl InvitationBook {
    pub fn new(group_id: GroupId) -> Self {
        Self {
            group_id,
            invitations: Vec::new(),
        }
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn records(&self) -> &[Invitation] {
        &self.invitations
    }

    /// Encodes the complete bounded invitation lifecycle checkpoint. Records
    /// sort by opaque invitation ID so a restart never depends on arrival order.
    pub fn encode_state(&self) -> Result<Vec<u8>, Error> {
        fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
            let length = u16::try_from(bytes.len()).map_err(|_| Error::Malformed)?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(bytes);
            Ok(())
        }

        let count = u8::try_from(self.invitations.len()).map_err(|_| Error::Malformed)?;
        if usize::from(count) > MAX_INVITATION_RECORDS {
            return Err(Error::Malformed);
        }
        let mut invitations = self.invitations.clone();
        invitations.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
        let mut out = Vec::new();
        out.extend_from_slice(INVITATION_BOOK_STATE_DOMAIN);
        out.extend_from_slice(self.group_id.as_bytes());
        out.push(count);
        for invitation in invitations {
            out.extend_from_slice(invitation.id.as_bytes());
            put_lp(&mut out, invitation.target.identity())?;
            put_lp(&mut out, invitation.target.device())?;
            out.extend_from_slice(&invitation.source_revision.to_be_bytes());
            out.extend_from_slice(&invitation.source_roster_digest);
            out.extend_from_slice(&invitation.policy_version.to_be_bytes());
            out.extend_from_slice(&invitation.expires_at.to_be_bytes());
            let (status, admitted_revision) = status_code(invitation.status);
            out.push(status);
            if let Some(revision) = admitted_revision {
                if revision == RESERVED_REVISION {
                    return Err(Error::ReservedRevision);
                }
                out.extend_from_slice(&revision.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Restores a canonical bounded invitation checkpoint for the requested
    /// group. This deliberately rejects an ambiguous or partially consumed
    /// state rather than inferring missing lifecycle information.
    pub fn decode_state(bytes: &[u8], expected_group_id: GroupId) -> Result<Self, Error> {
        fn take<'a>(cursor: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
            let (head, tail) = cursor.split_at_checked(count).ok_or(Error::Malformed)?;
            *cursor = tail;
            Ok(head)
        }
        fn take_u16(cursor: &mut &[u8]) -> Result<usize, Error> {
            Ok(usize::from(u16::from_be_bytes(
                take(cursor, 2)?.try_into().map_err(|_| Error::Malformed)?,
            )))
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
            let length = take_u16(cursor)?;
            Ok(take(cursor, length)?.to_vec())
        }

        let mut cursor = bytes;
        if !cursor.starts_with(INVITATION_BOOK_STATE_DOMAIN) {
            return Err(Error::Malformed);
        }
        cursor = &cursor[INVITATION_BOOK_STATE_DOMAIN.len()..];
        let encoded_group = GroupId::try_from(take(&mut cursor, crate::GROUP_ID_LEN)?)?;
        if encoded_group != expected_group_id {
            return Err(Error::Conflict);
        }
        let count = usize::from(*take(&mut cursor, 1)?.first().ok_or(Error::Malformed)?);
        if count > MAX_INVITATION_RECORDS {
            return Err(Error::Malformed);
        }
        let mut invitations = Vec::with_capacity(count);
        let mut previous_id = None;
        for _ in 0..count {
            let id = InvitationId::try_from(take(&mut cursor, 16)?)?;
            if previous_id
                .is_some_and(|previous: InvitationId| previous.as_bytes() >= id.as_bytes())
            {
                return Err(Error::NonCanonical);
            }
            previous_id = Some(id);
            let target = Member::new(take_lp(&mut cursor)?, take_lp(&mut cursor)?);
            let source_revision = take_u64(&mut cursor)?;
            let source_roster_digest: [u8; DIGEST_LEN] = take(&mut cursor, DIGEST_LEN)?
                .try_into()
                .map_err(|_| Error::Malformed)?;
            let policy_version = take_u32(&mut cursor)?;
            let expires_at = take_u64(&mut cursor)?;
            let status = match *take(&mut cursor, 1)?.first().ok_or(Error::Malformed)? {
                0 => InvitationStatus::Pending,
                1 => InvitationStatus::AcceptedPendingAdmission,
                2 => {
                    let revision = take_u64(&mut cursor)?;
                    if revision == RESERVED_REVISION {
                        return Err(Error::ReservedRevision);
                    }
                    InvitationStatus::Admitted { revision }
                }
                3 => InvitationStatus::Revoked,
                4 => InvitationStatus::Expired,
                _ => return Err(Error::Malformed),
            };
            let mut invitation = Invitation::new(
                id,
                expected_group_id,
                target,
                source_revision,
                source_roster_digest,
                policy_version,
                expires_at,
            )?;
            invitation.status = status;
            invitations.push(invitation);
        }
        if !cursor.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            group_id: expected_group_id,
            invitations,
        })
    }

    /// Creates an immutable pending record.  Exact retries return the current
    /// record; a reused ID with a different immutable field is a conflict.
    pub fn create(
        &mut self,
        authenticated_authority: &Member,
        authority: &Member,
        active_members: &[Member],
        invitation: Invitation,
        now: u64,
    ) -> Result<&Invitation, Error> {
        if authenticated_authority != authority {
            return Err(Error::Unauthorized);
        }
        if invitation.group_id != self.group_id {
            return Err(Error::Conflict);
        }
        if now >= invitation.expires_at {
            return Err(Error::Expired);
        }
        if active_members
            .iter()
            .any(|member| member == &invitation.target)
        {
            return Err(Error::Conflict);
        }
        if let Some(position) = self
            .invitations
            .iter()
            .position(|existing| existing.id == invitation.id)
        {
            if self.invitations[position].same_immutable_fields(&invitation) {
                return Ok(&self.invitations[position]);
            }
            return Err(Error::Conflict);
        }
        if self.invitations.len() == MAX_INVITATION_RECORDS {
            return Err(Error::OutboxFull);
        }
        self.invitations.push(invitation);
        Ok(self.invitations.last().expect("just inserted"))
    }

    /// Records target acceptance only.  Admission remains an authority action.
    pub fn accept(
        &mut self,
        id: InvitationId,
        authenticated_target: &Member,
        observed_revision: u64,
        observed_roster_digest: &[u8; DIGEST_LEN],
        now: u64,
    ) -> Result<&Invitation, Error> {
        let invitation = self.find_mut(id)?;
        if authenticated_target != &invitation.target {
            return Err(Error::WrongTarget);
        }
        if !invitation.source_matches(observed_revision, observed_roster_digest) {
            return Err(Error::StaleSource);
        }
        invitation.expire_if_due(now);
        match invitation.status {
            InvitationStatus::Pending => {
                invitation.status = InvitationStatus::AcceptedPendingAdmission;
                Ok(invitation)
            }
            InvitationStatus::AcceptedPendingAdmission | InvitationStatus::Admitted { .. } => {
                Ok(invitation)
            }
            InvitationStatus::Revoked => Err(Error::Revoked),
            InvitationStatus::Expired => Err(Error::Expired),
        }
    }

    /// Revocation wins over a previously accepted invitation.
    pub fn revoke(
        &mut self,
        id: InvitationId,
        authenticated_authority: &Member,
        authority: &Member,
        now: u64,
    ) -> Result<&Invitation, Error> {
        if authenticated_authority != authority {
            return Err(Error::Unauthorized);
        }
        let invitation = self.find_mut(id)?;
        invitation.expire_if_due(now);
        match invitation.status {
            InvitationStatus::Pending | InvitationStatus::AcceptedPendingAdmission => {
                invitation.status = InvitationStatus::Revoked;
                Ok(invitation)
            }
            InvitationStatus::Revoked => Ok(invitation),
            InvitationStatus::Expired => Err(Error::Expired),
            InvitationStatus::Admitted { .. } => Err(Error::WrongDisposition),
        }
    }

    /// Activates membership only through an authenticated authority successor.
    pub fn admit(
        &mut self,
        id: InvitationId,
        authenticated_authority: &Member,
        authority: &Member,
        accepted_revision: u64,
        now: u64,
    ) -> Result<&Invitation, Error> {
        if authenticated_authority != authority {
            return Err(Error::Unauthorized);
        }
        if accepted_revision == RESERVED_REVISION {
            return Err(Error::ReservedRevision);
        }
        let invitation = self.find_mut(id)?;
        invitation.expire_if_due(now);
        match invitation.status {
            InvitationStatus::AcceptedPendingAdmission => {
                invitation.status = InvitationStatus::Admitted {
                    revision: accepted_revision,
                };
                Ok(invitation)
            }
            InvitationStatus::Admitted { .. } => Ok(invitation),
            InvitationStatus::Pending => Err(Error::WrongDisposition),
            InvitationStatus::Revoked => Err(Error::Revoked),
            InvitationStatus::Expired => Err(Error::Expired),
        }
    }

    fn find_mut(&mut self, id: InvitationId) -> Result<&mut Invitation, Error> {
        self.invitations
            .iter_mut()
            .find(|invitation| invitation.id == id)
            .ok_or(Error::Malformed)
    }
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

    fn invitation(id: u8) -> Invitation {
        Invitation::new(
            InvitationId::new([id; 16]),
            group(),
            bob(),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap()
    }

    #[test]
    fn acceptance_does_not_activate_membership_and_admission_does() {
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation(7), 0)
            .unwrap();
        assert_eq!(
            book.accept(InvitationId::new([7; 16]), &bob(), 0, &[0; DIGEST_LEN], 1)
                .unwrap()
                .status,
            InvitationStatus::AcceptedPendingAdmission
        );
        assert_eq!(
            book.admit(InvitationId::new([7; 16]), &alice(), &alice(), 1, 2)
                .unwrap()
                .status,
            InvitationStatus::Admitted { revision: 1 }
        );
    }

    #[test]
    fn revocation_and_expiry_win_over_admission() {
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation(7), 0)
            .unwrap();
        book.accept(InvitationId::new([7; 16]), &bob(), 0, &[0; DIGEST_LEN], 1)
            .unwrap();
        book.revoke(InvitationId::new([7; 16]), &alice(), &alice(), 2)
            .unwrap();
        assert_eq!(
            book.admit(InvitationId::new([7; 16]), &alice(), &alice(), 1, 2),
            Err(Error::Revoked)
        );

        let mut expiring = InvitationBook::new(group());
        expiring
            .create(&alice(), &alice(), &[alice()], invitation(8), 0)
            .unwrap();
        assert_eq!(
            expiring.accept(InvitationId::new([8; 16]), &bob(), 0, &[0; DIGEST_LEN], 10),
            Err(Error::Expired)
        );
    }

    #[test]
    fn retries_keep_the_committed_record_and_changed_fields_conflict() {
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation(7), 0)
            .unwrap();
        assert_eq!(
            book.create(&alice(), &alice(), &[alice()], invitation(7), 1)
                .unwrap()
                .status,
            InvitationStatus::Pending
        );
        let mut conflicting = invitation(7);
        conflicting.expires_at = 11;
        assert_eq!(
            book.create(&alice(), &alice(), &[alice()], conflicting, 1),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn source_and_authenticated_target_are_checked_before_state_changes() {
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation(7), 0)
            .unwrap();
        assert_eq!(
            book.accept(InvitationId::new([7; 16]), &alice(), 0, &[0; DIGEST_LEN], 1),
            Err(Error::WrongTarget)
        );
        assert_eq!(
            book.accept(InvitationId::new([7; 16]), &bob(), 1, &[0; DIGEST_LEN], 1),
            Err(Error::StaleSource)
        );
        assert_eq!(book.records()[0].status, InvitationStatus::Pending);
    }

    #[test]
    fn a_record_for_another_group_cannot_enter_this_books_lifecycle() {
        let mut book = InvitationBook::new(group());
        let other_group = GroupId::new(*b"other-group-id!!");
        let other_invitation = Invitation::new(
            InvitationId::new([7; 16]),
            other_group,
            bob(),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        assert_eq!(
            book.create(&alice(), &alice(), &[alice()], other_invitation, 0),
            Err(Error::Conflict)
        );
        assert!(book.records().is_empty());
    }

    #[test]
    fn invitation_book_state_round_trips_every_lifecycle_disposition() {
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation(8), 0)
            .unwrap();
        book.create(&alice(), &alice(), &[alice()], invitation(7), 0)
            .unwrap();
        book.accept(InvitationId::new([7; 16]), &bob(), 0, &[0; DIGEST_LEN], 1)
            .unwrap();
        book.admit(InvitationId::new([7; 16]), &alice(), &alice(), 1, 2)
            .unwrap();
        let state = book.encode_state().unwrap();
        let restored = InvitationBook::decode_state(&state, group()).unwrap();
        assert_eq!(restored.records().len(), 2);
        assert_eq!(
            restored.records()[0].status,
            InvitationStatus::Admitted { revision: 1 }
        );
        assert_eq!(restored.records()[1].status, InvitationStatus::Pending);
        assert_eq!(restored.encode_state().unwrap(), state);
    }

    #[test]
    fn invitation_book_state_refuses_reordered_or_trailing_records() {
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation(7), 0)
            .unwrap();
        book.create(&alice(), &alice(), &[alice()], invitation(8), 0)
            .unwrap();
        let state = book.encode_state().unwrap();
        let domain_len = INVITATION_BOOK_STATE_DOMAIN.len();
        let first_id = domain_len + crate::GROUP_ID_LEN + 1;
        let record_len =
            16 + 2 + bob().identity().len() + 2 + bob().device().len() + 8 + DIGEST_LEN + 4 + 8 + 1;
        let mut reordered = state.clone();
        let first = reordered[first_id..first_id + record_len].to_vec();
        reordered.copy_within(first_id + record_len..first_id + 2 * record_len, first_id);
        reordered[first_id + record_len..first_id + 2 * record_len].copy_from_slice(&first);
        assert_eq!(
            InvitationBook::decode_state(&reordered, group()),
            Err(Error::NonCanonical)
        );
        let mut trailing = state;
        trailing.push(0);
        assert_eq!(
            InvitationBook::decode_state(&trailing, group()),
            Err(Error::Malformed)
        );
    }
}
