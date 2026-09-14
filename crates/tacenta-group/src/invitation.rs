//! Product policy for the bounded invitation lifecycle.

use crate::{DIGEST_LEN, Error, GroupId, Member, POLICY_VERSION_V1, RESERVED_REVISION};

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
}
