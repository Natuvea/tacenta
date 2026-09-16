//! Durable state for exact-ciphertext roster-control handoffs.

use tacenta_core::crypto::groups::payload_commitment;
use tacenta_group::{Error as GroupError, GroupPayload, MAX_DEVICE_LEN, MAX_IDENTITY_LEN, Member};

const DOMAIN: &[u8] = b"Tacenta Group Control Outbox State v1";
const MAX_HANDOFFS: usize = 8;
const MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    Prepared,
    HandedOff,
    RelayAccepted,
    ExhaustedUnknown,
    Cancelled,
    CancelledAfterHandoff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handoff {
    pub(crate) recipient: Member,
    pub(crate) payload: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) attempts_reserved: u8,
    pub(crate) disposition: Disposition,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Outbox {
    handoffs: Vec<Handoff>,
}

impl Outbox {
    pub(crate) fn record_prepared(
        &mut self,
        recipient: Member,
        payload: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<(), GroupError> {
        let commitment = payload_commitment(&payload);
        if let Some(existing) = self.handoffs.iter().find(|existing| {
            existing.recipient == recipient && payload_commitment(&existing.payload) == commitment
        }) {
            return if existing.payload == payload && existing.ciphertext == ciphertext {
                Ok(())
            } else {
                Err(GroupError::Conflict)
            };
        }
        if self.handoffs.len() == MAX_HANDOFFS
            || !matches!(
                GroupPayload::decode(&payload),
                Ok(GroupPayload::Roster(_))
                    | Ok(GroupPayload::InvitationBootstrap(_))
                    | Ok(GroupPayload::InvitationAcceptance(_))
                    | Ok(GroupPayload::InvitationRevocation(_))
            )
        {
            return Err(GroupError::OutboxFull);
        }
        self.handoffs.push(Handoff {
            recipient,
            payload,
            ciphertext,
            attempts_reserved: 0,
            disposition: Disposition::Prepared,
        });
        Ok(())
    }

    pub(crate) fn reserve(
        &mut self,
        recipient: &Member,
        payload: &[u8],
    ) -> Result<Handoff, GroupError> {
        let commitment = payload_commitment(payload);
        let handoff = self
            .handoffs
            .iter_mut()
            .find(|handoff| {
                handoff.recipient == *recipient
                    && payload_commitment(&handoff.payload) == commitment
            })
            .ok_or(GroupError::Malformed)?;
        match handoff.disposition {
            Disposition::Prepared | Disposition::HandedOff => {}
            Disposition::RelayAccepted
            | Disposition::ExhaustedUnknown
            | Disposition::Cancelled
            | Disposition::CancelledAfterHandoff => {
                return Err(GroupError::WrongDisposition);
            }
        }
        if handoff.attempts_reserved == MAX_ATTEMPTS {
            handoff.disposition = Disposition::ExhaustedUnknown;
            return Ok(handoff.clone());
        }
        handoff.attempts_reserved += 1;
        handoff.disposition = Disposition::HandedOff;
        Ok(handoff.clone())
    }

    /// Stops any unsent control, or retry of an uncertain prior handoff, for
    /// one recipient while retaining the exact ciphertext as durable evidence.
    pub(crate) fn cancel_for_recipient(&mut self, recipient: &Member) {
        for handoff in &mut self.handoffs {
            if handoff.recipient != *recipient {
                continue;
            }
            handoff.disposition = match handoff.disposition {
                Disposition::Prepared => Disposition::Cancelled,
                Disposition::HandedOff => Disposition::CancelledAfterHandoff,
                disposition => disposition,
            };
        }
    }

    pub(crate) fn handoff(
        &self,
        recipient: &Member,
        payload: &[u8],
    ) -> Result<Handoff, GroupError> {
        let commitment = payload_commitment(payload);
        self.handoffs
            .iter()
            .find(|handoff| {
                handoff.recipient == *recipient
                    && payload_commitment(&handoff.payload) == commitment
            })
            .cloned()
            .ok_or(GroupError::Malformed)
    }

    pub(crate) fn accept(&mut self, recipient: &Member, payload: &[u8]) -> Result<(), GroupError> {
        let commitment = payload_commitment(payload);
        let handoff = self
            .handoffs
            .iter_mut()
            .find(|handoff| {
                handoff.recipient == *recipient
                    && payload_commitment(&handoff.payload) == commitment
            })
            .ok_or(GroupError::Malformed)?;
        if handoff.disposition != Disposition::HandedOff {
            return Err(GroupError::WrongDisposition);
        }
        handoff.disposition = Disposition::RelayAccepted;
        Ok(())
    }

    pub(crate) fn encode_state(&self) -> Result<Vec<u8>, GroupError> {
        fn put(out: &mut Vec<u8>, value: &[u8]) -> Result<(), GroupError> {
            out.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| GroupError::Malformed)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(value);
            Ok(())
        }
        if self.handoffs.len() > MAX_HANDOFFS {
            return Err(GroupError::OutboxFull);
        }
        let mut entries = self.handoffs.clone();
        entries.sort_by(|a, b| {
            payload_commitment(&a.payload)
                .cmp(&payload_commitment(&b.payload))
                .then_with(|| a.recipient.identity().cmp(b.recipient.identity()))
                .then_with(|| a.recipient.device().cmp(b.recipient.device()))
        });
        let mut state = DOMAIN.to_vec();
        state.push(u8::try_from(entries.len()).map_err(|_| GroupError::Malformed)?);
        for entry in entries {
            put(&mut state, entry.recipient.identity())?;
            put(&mut state, entry.recipient.device())?;
            put(&mut state, &entry.payload)?;
            put(&mut state, &entry.ciphertext)?;
            state.push(entry.attempts_reserved);
            state.push(match entry.disposition {
                Disposition::Prepared => 0,
                Disposition::HandedOff => 1,
                Disposition::RelayAccepted => 2,
                Disposition::ExhaustedUnknown => 3,
                Disposition::Cancelled => 4,
                Disposition::CancelledAfterHandoff => 5,
            });
        }
        Ok(state)
    }

    pub(crate) fn decode_state(bytes: &[u8]) -> Result<Self, GroupError> {
        fn take<'a>(cursor: &mut &'a [u8], count: usize) -> Result<&'a [u8], GroupError> {
            let (head, tail) = cursor
                .split_at_checked(count)
                .ok_or(GroupError::Malformed)?;
            *cursor = tail;
            Ok(head)
        }
        fn take_lp(cursor: &mut &[u8]) -> Result<Vec<u8>, GroupError> {
            let length: [u8; 4] = take(cursor, 4)?
                .try_into()
                .map_err(|_| GroupError::Malformed)?;
            Ok(take(
                cursor,
                usize::try_from(u32::from_be_bytes(length)).map_err(|_| GroupError::Malformed)?,
            )?
            .to_vec())
        }
        if !bytes.starts_with(DOMAIN) {
            return Err(GroupError::Malformed);
        }
        let mut cursor = &bytes[DOMAIN.len()..];
        let count = usize::from(*take(&mut cursor, 1)?.first().ok_or(GroupError::Malformed)?);
        if count > MAX_HANDOFFS {
            return Err(GroupError::OutboxFull);
        }
        let mut outbox = Self::default();
        for _ in 0..count {
            let identity = take_lp(&mut cursor)?;
            let device = take_lp(&mut cursor)?;
            if identity.len() > MAX_IDENTITY_LEN || device.len() > MAX_DEVICE_LEN {
                return Err(GroupError::Malformed);
            }
            let payload = take_lp(&mut cursor)?;
            let ciphertext = take_lp(&mut cursor)?;
            let attempts = *take(&mut cursor, 1)?.first().ok_or(GroupError::Malformed)?;
            let disposition = match *take(&mut cursor, 1)?.first().ok_or(GroupError::Malformed)? {
                0 => Disposition::Prepared,
                1 => Disposition::HandedOff,
                2 => Disposition::RelayAccepted,
                3 => Disposition::ExhaustedUnknown,
                4 => Disposition::Cancelled,
                5 => Disposition::CancelledAfterHandoff,
                _ => return Err(GroupError::Malformed),
            };
            if attempts > MAX_ATTEMPTS
                || (disposition == Disposition::Prepared && attempts != 0)
                || (disposition == Disposition::HandedOff && attempts == 0)
            {
                return Err(GroupError::Malformed);
            }
            outbox.record_prepared(Member::new(identity, device), payload, ciphertext)?;
            let handoff = outbox.handoffs.last_mut().expect("recorded handoff");
            handoff.attempts_reserved = attempts;
            handoff.disposition = disposition;
        }
        if !cursor.is_empty() {
            return Err(GroupError::Malformed);
        }
        let canonical = outbox.encode_state()?;
        if canonical != bytes {
            return Err(GroupError::NonCanonical);
        }
        Ok(outbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacenta_group::{
        DIGEST_LEN, GroupId, InvitationAcceptance, InvitationId, POLICY_VERSION_V1, Roster,
    };

    fn alice() -> Member {
        Member::new(b"alice".to_vec(), vec![1])
    }
    fn bob() -> Member {
        Member::new(b"bob".to_vec(), vec![1])
    }

    #[test]
    fn exact_control_ciphertext_survives_reservation_and_recovery() {
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
        let payload = GroupPayload::Roster(roster).encode().unwrap();
        let mut outbox = Outbox::default();
        outbox
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();
        assert_eq!(
            outbox.reserve(&bob(), &payload).unwrap().ciphertext,
            vec![7, 8]
        );
        let state = outbox.encode_state().unwrap();
        assert_eq!(Outbox::decode_state(&state), Ok(outbox));
    }

    #[test]
    fn exhausted_control_handoff_stays_terminal_after_its_final_checkpoint() {
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
        let payload = GroupPayload::Roster(roster).encode().unwrap();
        let mut outbox = Outbox::default();
        outbox
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();

        for attempt in 1..=MAX_ATTEMPTS {
            let handoff = outbox.reserve(&bob(), &payload).unwrap();
            assert_eq!(handoff.attempts_reserved, attempt);
            assert_eq!(handoff.disposition, Disposition::HandedOff);
        }
        let exhausted = outbox.reserve(&bob(), &payload).unwrap();
        assert_eq!(exhausted.attempts_reserved, MAX_ATTEMPTS);
        assert_eq!(exhausted.disposition, Disposition::ExhaustedUnknown);
        assert_eq!(
            outbox.reserve(&bob(), &payload),
            Err(GroupError::WrongDisposition)
        );

        let state = outbox.encode_state().unwrap();
        assert_eq!(Outbox::decode_state(&state), Ok(outbox));
    }

    #[test]
    fn recipient_cancellation_retains_evidence_but_blocks_later_dispatch() {
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
        let payload = GroupPayload::Roster(roster).encode().unwrap();
        let mut outbox = Outbox::default();
        outbox
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();
        outbox.cancel_for_recipient(&bob());
        assert_eq!(
            outbox.handoff(&bob(), &payload).unwrap().disposition,
            Disposition::Cancelled
        );
        assert_eq!(
            outbox.reserve(&bob(), &payload),
            Err(GroupError::WrongDisposition)
        );

        let mut retried = Outbox::default();
        retried
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();
        retried.reserve(&bob(), &payload).unwrap();
        retried.cancel_for_recipient(&bob());
        assert_eq!(
            retried.handoff(&bob(), &payload).unwrap().disposition,
            Disposition::CancelledAfterHandoff
        );
        assert_eq!(
            Outbox::decode_state(&retried.encode_state().unwrap()),
            Ok(retried)
        );
    }

    #[test]
    fn invitation_acceptance_uses_the_same_exact_ciphertext_handoff() {
        let payload = GroupPayload::InvitationAcceptance(
            InvitationAcceptance::new(
                GroupId::new(*b"bounded-group-id"),
                InvitationId::new([7; 16]),
                0,
                [0; DIGEST_LEN],
            )
            .unwrap(),
        )
        .encode()
        .unwrap();
        let mut outbox = Outbox::default();
        outbox
            .record_prepared(alice(), payload.clone(), vec![7, 8])
            .unwrap();
        assert_eq!(
            outbox.reserve(&alice(), &payload).unwrap().ciphertext,
            vec![7, 8]
        );
        assert_eq!(
            Outbox::decode_state(&outbox.encode_state().unwrap()),
            Ok(outbox)
        );
    }
}
