//! Accepted bounded-roster progression after core commitment verification.

use crate::{DIGEST_LEN, Member, Roster};

const ROSTER_VIEW_STATE_DOMAIN: &[u8] = b"Tacenta Group Roster View State v1";

/// Why a candidate roster cannot replace the accepted view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterRefusal {
    WrongAuthority,
    WrongGroup,
    InvalidGenesis,
    StaleRevision,
    MissingPredecessor,
    Conflict,
    AuthorityTransfer,
    PolicyChange,
    Reopened,
    MissingAuthorityMember,
}

/// The result of considering a complete core-verified roster preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterDisposition {
    Accepted,
    Duplicate,
    Rejected(RosterRefusal),
}

/// One locally accepted roster. The integration must calculate each supplied
/// digest with the standalone-core helper over `Roster::encode()` before this
/// policy state is called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterView {
    roster: Roster,
    digest: [u8; DIGEST_LEN],
}

impl RosterView {
    /// Starts the single-authority bounded profile from its only valid genesis.
    pub fn accept_genesis(
        authenticated_authority: &Member,
        roster: Roster,
        digest: [u8; DIGEST_LEN],
    ) -> Result<Self, RosterRefusal> {
        if authenticated_authority != &roster.authority {
            return Err(RosterRefusal::WrongAuthority);
        }
        if roster.revision != 0
            || roster.predecessor_digest != [0; DIGEST_LEN]
            || roster.closed
            || roster.members.as_slice() != [roster.authority.clone()]
        {
            return Err(RosterRefusal::InvalidGenesis);
        }
        Ok(Self { roster, digest })
    }

    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    pub fn digest(&self) -> &[u8; DIGEST_LEN] {
        &self.digest
    }

    /// Encodes the currently accepted, core-bound roster checkpoint.
    pub fn encode_state(&self) -> Result<Vec<u8>, crate::Error> {
        let roster = self.roster.encode()?;
        let mut out = ROSTER_VIEW_STATE_DOMAIN.to_vec();
        out.extend_from_slice(
            &u32::try_from(roster.len())
                .map_err(|_| crate::Error::Malformed)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&roster);
        out.extend_from_slice(&self.digest);
        Ok(out)
    }

    /// Restores an accepted checkpoint. `pinned_authority` comes from the
    /// authority channel that bootstrapped this group, not from the checkpoint.
    pub fn decode_state(
        bytes: &[u8],
        pinned_authority: &Member,
        roster_commitment: impl Fn(&[u8]) -> [u8; DIGEST_LEN],
    ) -> Result<Self, RosterRefusal> {
        if !bytes.starts_with(ROSTER_VIEW_STATE_DOMAIN) {
            return Err(RosterRefusal::InvalidGenesis);
        }
        let mut cursor = &bytes[ROSTER_VIEW_STATE_DOMAIN.len()..];
        let (length, rest) = cursor
            .split_at_checked(4)
            .ok_or(RosterRefusal::InvalidGenesis)?;
        cursor = rest;
        let length = usize::try_from(u32::from_be_bytes(
            length
                .try_into()
                .map_err(|_| RosterRefusal::InvalidGenesis)?,
        ))
        .map_err(|_| RosterRefusal::InvalidGenesis)?;
        let (roster_bytes, digest) = cursor
            .split_at_checked(length)
            .ok_or(RosterRefusal::InvalidGenesis)?;
        if digest.len() != DIGEST_LEN {
            return Err(RosterRefusal::InvalidGenesis);
        }
        let roster = Roster::decode(roster_bytes).map_err(|_| RosterRefusal::InvalidGenesis)?;
        let digest: [u8; DIGEST_LEN] = digest
            .try_into()
            .map_err(|_| RosterRefusal::InvalidGenesis)?;
        if &roster.authority != pinned_authority {
            return Err(RosterRefusal::WrongAuthority);
        }
        if digest != roster_commitment(roster_bytes) {
            return Err(RosterRefusal::Conflict);
        }
        if roster.revision == 0 {
            return Self::accept_genesis(pinned_authority, roster, digest);
        }
        if !roster
            .members
            .iter()
            .any(|member| member == pinned_authority)
        {
            return Err(RosterRefusal::MissingAuthorityMember);
        }
        Ok(Self { roster, digest })
    }

    /// Whether this accepted view grants the complete identity/device binding
    /// application membership. Observing control history alone does not.
    pub fn is_active(&self, member: &Member) -> bool {
        !self.roster.closed && self.roster.members.iter().any(|known| known == member)
    }

    pub fn accept_successor(
        &mut self,
        authenticated_authority: &Member,
        candidate: Roster,
        digest: [u8; DIGEST_LEN],
    ) -> RosterDisposition {
        if authenticated_authority != &self.roster.authority {
            return RosterDisposition::Rejected(RosterRefusal::WrongAuthority);
        }
        if candidate.group_id != self.roster.group_id {
            return RosterDisposition::Rejected(RosterRefusal::WrongGroup);
        }
        if candidate.authority != self.roster.authority {
            return RosterDisposition::Rejected(RosterRefusal::AuthorityTransfer);
        }
        if candidate.policy_version != self.roster.policy_version {
            return RosterDisposition::Rejected(RosterRefusal::PolicyChange);
        }
        if !candidate
            .members
            .iter()
            .any(|member| member == &candidate.authority)
        {
            return RosterDisposition::Rejected(RosterRefusal::MissingAuthorityMember);
        }
        if candidate.revision < self.roster.revision {
            return RosterDisposition::Rejected(RosterRefusal::StaleRevision);
        }
        if candidate.revision == self.roster.revision {
            return if candidate == self.roster && digest == self.digest {
                RosterDisposition::Duplicate
            } else {
                RosterDisposition::Rejected(RosterRefusal::Conflict)
            };
        }
        if candidate.revision != self.roster.revision.saturating_add(1)
            || candidate.predecessor_digest != self.digest
        {
            return RosterDisposition::Rejected(RosterRefusal::MissingPredecessor);
        }
        if self.roster.closed && !candidate.closed {
            return RosterDisposition::Rejected(RosterRefusal::Reopened);
        }

        self.roster = candidate;
        self.digest = digest;
        RosterDisposition::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GroupId, POLICY_VERSION_V1, Roster};

    fn group() -> GroupId {
        GroupId::new(*b"bounded-group-id")
    }

    fn alice() -> Member {
        Member::new(b"alice".to_vec(), vec![1])
    }

    fn bob() -> Member {
        Member::new(b"bob".to_vec(), vec![1])
    }

    fn carol() -> Member {
        Member::new(b"carol".to_vec(), vec![1])
    }

    fn roster(revision: u64, predecessor_digest: [u8; DIGEST_LEN], members: Vec<Member>) -> Roster {
        Roster::new(
            group(),
            revision,
            predecessor_digest,
            alice(),
            POLICY_VERSION_V1,
            false,
            members,
        )
        .unwrap()
    }

    #[test]
    fn pending_observer_becomes_active_only_at_its_admission_revision() {
        let mut view = RosterView::accept_genesis(
            &alice(),
            roster(0, [0; DIGEST_LEN], vec![alice()]),
            [1; DIGEST_LEN],
        )
        .unwrap();
        assert!(!view.is_active(&bob()));
        assert_eq!(
            view.accept_successor(
                &alice(),
                roster(1, [1; DIGEST_LEN], vec![alice(), bob()]),
                [2; DIGEST_LEN],
            ),
            RosterDisposition::Accepted
        );
        assert!(view.is_active(&bob()));
        assert!(!view.is_active(&carol()));
        assert_eq!(
            view.accept_successor(
                &alice(),
                roster(2, [2; DIGEST_LEN], vec![alice(), bob(), carol()]),
                [3; DIGEST_LEN],
            ),
            RosterDisposition::Accepted
        );
        assert!(view.is_active(&carol()));
    }

    #[test]
    fn successor_refusals_preserve_the_last_accepted_view() {
        let mut view = RosterView::accept_genesis(
            &alice(),
            roster(0, [0; DIGEST_LEN], vec![alice()]),
            [1; DIGEST_LEN],
        )
        .unwrap();
        let before = view.clone();
        assert_eq!(
            view.accept_successor(
                &bob(),
                roster(1, [1; DIGEST_LEN], vec![alice(), bob()]),
                [2; DIGEST_LEN],
            ),
            RosterDisposition::Rejected(RosterRefusal::WrongAuthority)
        );
        assert_eq!(view, before);
        assert_eq!(
            view.accept_successor(
                &alice(),
                roster(2, [1; DIGEST_LEN], vec![alice(), bob()]),
                [2; DIGEST_LEN],
            ),
            RosterDisposition::Rejected(RosterRefusal::MissingPredecessor)
        );
        assert_eq!(view, before);
    }

    #[test]
    fn exact_current_roster_is_a_duplicate_but_a_same_revision_change_conflicts() {
        let initial = roster(0, [0; DIGEST_LEN], vec![alice()]);
        let mut view =
            RosterView::accept_genesis(&alice(), initial.clone(), [1; DIGEST_LEN]).unwrap();
        assert_eq!(
            view.accept_successor(&alice(), initial.clone(), [1; DIGEST_LEN]),
            RosterDisposition::Duplicate
        );
        let mut conflict = initial;
        conflict.closed = true;
        assert_eq!(
            view.accept_successor(&alice(), conflict, [1; DIGEST_LEN]),
            RosterDisposition::Rejected(RosterRefusal::Conflict)
        );
    }

    #[test]
    fn a_core_bound_roster_checkpoint_restores_with_the_pinned_authority() {
        let mut view = RosterView::accept_genesis(
            &alice(),
            roster(0, [0; DIGEST_LEN], vec![alice()]),
            [1; DIGEST_LEN],
        )
        .unwrap();
        assert_eq!(
            view.accept_successor(
                &alice(),
                roster(1, [1; DIGEST_LEN], vec![alice(), bob()]),
                [2; DIGEST_LEN],
            ),
            RosterDisposition::Accepted
        );
        let encoded = view.encode_state().unwrap();
        assert_eq!(
            RosterView::decode_state(&encoded, &alice(), |_| [2; DIGEST_LEN]),
            Ok(view.clone())
        );
        assert_eq!(
            RosterView::decode_state(&encoded, &bob(), |_| [2; DIGEST_LEN]),
            Err(RosterRefusal::WrongAuthority)
        );
    }
}
