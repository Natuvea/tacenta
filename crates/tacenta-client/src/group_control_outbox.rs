//! Durable state for exact-ciphertext roster-control handoffs (0124).
//!
//! The outbox holds at most eight live handoffs and sixteen retained terminal
//! handoffs, so a finished handoff never wedges the group (0133). The third
//! reservation of a handoff is its final attempt and enters `exhausted_unknown`
//! before it is sent, exactly as in the application outbox (0106, 0134).

use tacenta_core::crypto::groups::payload_commitment;
use tacenta_group::{Error as GroupError, GroupPayload, MAX_DEVICE_LEN, MAX_IDENTITY_LEN, Member};

const DOMAIN: &[u8] = b"Tacenta Group Control Outbox State v2";
/// Handoffs that are not yet terminal (`prepared`, `handed_off`).
const MAX_LIVE_HANDOFFS: usize = 8;
/// Terminal handoffs kept as evidence; the oldest are dropped beyond this.
const MAX_TERMINAL_HANDOFFS: usize = 16;
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

/// The canonical order of entries: payload commitment, then recipient. The
/// live vector is kept in it, so a state and its decoding compare equal.
fn canonical_order(a: &Handoff, b: &Handoff) -> std::cmp::Ordering {
    payload_commitment(&a.payload)
        .cmp(&payload_commitment(&b.payload))
        .then_with(|| a.recipient.identity().cmp(b.recipient.identity()))
        .then_with(|| a.recipient.device().cmp(b.recipient.device()))
}

impl Disposition {
    /// A terminal handoff never sends again; it is retained only as evidence.
    fn is_terminal(self) -> bool {
        !matches!(self, Disposition::Prepared | Disposition::HandedOff)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Handoff {
    pub(crate) recipient: Member,
    pub(crate) payload: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) attempts_reserved: u8,
    pub(crate) disposition: Disposition,
    /// Allocation order, used only to decide which terminal entry is oldest.
    pub(crate) sequence: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Outbox {
    handoffs: Vec<Handoff>,
}

impl Outbox {
    fn live(&self) -> usize {
        self.handoffs
            .iter()
            .filter(|handoff| !handoff.disposition.is_terminal())
            .count()
    }

    /// Drops the oldest terminal handoffs beyond the retained bound.
    fn reclaim(&mut self) {
        loop {
            let terminal = self
                .handoffs
                .iter()
                .filter(|handoff| handoff.disposition.is_terminal())
                .count();
            if terminal <= MAX_TERMINAL_HANDOFFS {
                return;
            }
            let oldest = self
                .handoffs
                .iter()
                .enumerate()
                .filter(|(_, handoff)| handoff.disposition.is_terminal())
                .min_by_key(|(_, handoff)| handoff.sequence)
                .map(|(index, _)| index)
                .expect("a terminal handoff exists above the bound");
            self.handoffs.remove(oldest);
        }
    }

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
        if self.live() >= MAX_LIVE_HANDOFFS
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
        let sequence = self
            .handoffs
            .iter()
            .map(|handoff| handoff.sequence)
            .max()
            .map_or(0, |highest| highest.saturating_add(1));
        self.handoffs.push(Handoff {
            recipient,
            payload,
            ciphertext,
            attempts_reserved: 0,
            disposition: Disposition::Prepared,
            sequence,
        });
        self.handoffs.sort_by(canonical_order);
        self.reclaim();
        Ok(())
    }

    /// Reserves the next attempt for an exact prepared handoff. The third
    /// reservation is the final attempt: it returns the handoff with
    /// `exhausted_unknown` already recorded, so its bytes may be sent once and
    /// no fourth reservation exists (0134).
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
        handoff.attempts_reserved += 1;
        handoff.disposition = if handoff.attempts_reserved == MAX_ATTEMPTS {
            Disposition::ExhaustedUnknown
        } else {
            Disposition::HandedOff
        };
        let reserved = handoff.clone();
        self.reclaim();
        Ok(reserved)
    }

    /// Stops any unsent control, or retry of an uncertain prior handoff, for
    /// one recipient while retaining the exact ciphertext as durable evidence.
    pub(crate) fn cancel_non_revocation_for_recipient(&mut self, recipient: &Member) {
        for handoff in &mut self.handoffs {
            if handoff.recipient != *recipient
                || matches!(
                    GroupPayload::decode(&handoff.payload),
                    Ok(GroupPayload::InvitationRevocation(_))
                )
            {
                continue;
            }
            handoff.disposition = match handoff.disposition {
                Disposition::Prepared => Disposition::Cancelled,
                Disposition::HandedOff => Disposition::CancelledAfterHandoff,
                disposition => disposition,
            };
        }
        self.reclaim();
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
        // The final attempt is `exhausted_unknown` from its reservation, before
        // it is sent, so it is accepted from that state too (0135).
        if !matches!(
            handoff.disposition,
            Disposition::HandedOff | Disposition::ExhaustedUnknown
        ) {
            return Err(GroupError::WrongDisposition);
        }
        handoff.disposition = Disposition::RelayAccepted;
        self.reclaim();
        Ok(())
    }

    /// Every retained handoff that has not reached a terminal disposition.
    pub(crate) fn pending(&self) -> Vec<Handoff> {
        self.handoffs
            .iter()
            .filter(|handoff| !handoff.disposition.is_terminal())
            .cloned()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn len_for_tests(&self) -> usize {
        self.handoffs.len()
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
        let terminal = self
            .handoffs
            .iter()
            .filter(|handoff| handoff.disposition.is_terminal())
            .count();
        if self.live() > MAX_LIVE_HANDOFFS || terminal > MAX_TERMINAL_HANDOFFS {
            return Err(GroupError::OutboxFull);
        }
        let mut entries = self.handoffs.clone();
        entries.sort_by(canonical_order);
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
            state.extend_from_slice(&entry.sequence.to_be_bytes());
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
        if count > MAX_LIVE_HANDOFFS + MAX_TERMINAL_HANDOFFS {
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
            let sequence = u64::from_be_bytes(
                take(&mut cursor, 8)?
                    .try_into()
                    .map_err(|_| GroupError::Malformed)?,
            );
            if attempts > MAX_ATTEMPTS
                || (disposition == Disposition::Prepared && attempts != 0)
                || (disposition == Disposition::HandedOff
                    && (attempts == 0 || attempts == MAX_ATTEMPTS))
                || (disposition == Disposition::ExhaustedUnknown && attempts != MAX_ATTEMPTS)
                || (disposition == Disposition::Cancelled && attempts != 0)
                || (disposition == Disposition::CancelledAfterHandoff && attempts == 0)
                || !matches!(
                    GroupPayload::decode(&payload),
                    Ok(GroupPayload::Roster(_))
                        | Ok(GroupPayload::InvitationBootstrap(_))
                        | Ok(GroupPayload::InvitationAcceptance(_))
                        | Ok(GroupPayload::InvitationRevocation(_))
                )
            {
                return Err(GroupError::Malformed);
            }
            let recipient = Member::new(identity, device);
            let commitment = payload_commitment(&payload);
            if outbox.handoffs.iter().any(|known| {
                known.sequence == sequence
                    || (known.recipient == recipient
                        && payload_commitment(&known.payload) == commitment)
            }) {
                return Err(GroupError::Malformed);
            }
            outbox.handoffs.push(Handoff {
                recipient,
                payload,
                ciphertext,
                attempts_reserved: attempts,
                disposition,
                sequence,
            });
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

        // Two ordinary attempts, then the third reservation is the final one
        // and is exhausted before it is sent (0106, 0134).
        for attempt in 1..=2 {
            let handoff = outbox.reserve(&bob(), &payload).unwrap();
            assert_eq!(handoff.attempts_reserved, attempt);
            assert_eq!(handoff.disposition, Disposition::HandedOff);
        }
        let exhausted = outbox.reserve(&bob(), &payload).unwrap();
        assert_eq!(exhausted.attempts_reserved, 3);
        assert_eq!(exhausted.disposition, Disposition::ExhaustedUnknown);
        assert_eq!(
            outbox.reserve(&bob(), &payload),
            Err(GroupError::WrongDisposition)
        );

        let state = outbox.encode_state().unwrap();
        assert_eq!(Outbox::decode_state(&state), Ok(outbox));
    }

    #[test]
    fn the_final_attempt_is_accepted_from_exhausted_unknown_and_survives_encoding() {
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
        // Not accepted before any reservation.
        assert_eq!(
            outbox.accept(&bob(), &payload),
            Err(GroupError::WrongDisposition)
        );
        for _ in 0..3 {
            outbox.reserve(&bob(), &payload).unwrap();
        }
        assert_eq!(
            outbox.handoff(&bob(), &payload).unwrap().disposition,
            Disposition::ExhaustedUnknown
        );
        outbox.accept(&bob(), &payload).unwrap();
        let accepted = outbox.handoff(&bob(), &payload).unwrap();
        assert_eq!(accepted.disposition, Disposition::RelayAccepted);
        assert_eq!(accepted.attempts_reserved, 3);
        // Accepted once; a second acceptance and a fourth reservation refuse.
        assert_eq!(
            outbox.accept(&bob(), &payload),
            Err(GroupError::WrongDisposition)
        );
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
        outbox.cancel_non_revocation_for_recipient(&bob());
        assert_eq!(
            outbox.handoff(&bob(), &payload).unwrap().disposition,
            Disposition::Cancelled
        );
        assert_eq!(
            outbox.reserve(&bob(), &payload),
            Err(GroupError::WrongDisposition)
        );
        let mut malformed_cancelled = outbox.encode_state().unwrap();
        // The entry ends with attempts, disposition and an eight-byte sequence.
        let cancelled_attempt = malformed_cancelled.len() - 10;
        malformed_cancelled[cancelled_attempt] = 1;
        assert_eq!(
            Outbox::decode_state(&malformed_cancelled),
            Err(GroupError::Malformed)
        );

        let mut retried = Outbox::default();
        retried
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();
        retried.reserve(&bob(), &payload).unwrap();
        retried.cancel_non_revocation_for_recipient(&bob());
        assert_eq!(
            retried.handoff(&bob(), &payload).unwrap().disposition,
            Disposition::CancelledAfterHandoff
        );
        let state = retried.encode_state().unwrap();
        assert_eq!(Outbox::decode_state(&state), Ok(retried));
        let mut malformed_after_handoff = state;
        let after_handoff_attempt = malformed_after_handoff.len() - 10;
        malformed_after_handoff[after_handoff_attempt] = 0;
        assert_eq!(
            Outbox::decode_state(&malformed_after_handoff),
            Err(GroupError::Malformed)
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

    fn decode_after_patching(
        state: &mut [u8],
        attempts_from_end: usize,
        attempts: u8,
    ) -> Result<Outbox, GroupError> {
        let at = state.len() - attempts_from_end;
        state[at] = attempts;
        Outbox::decode_state(state)
    }

    #[test]
    fn a_state_with_an_impossible_attempt_count_is_refused() {
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
        // Each entry ends with attempts, disposition and an eight-byte sequence.
        let attempts_from_end = 10;

        let mut handed_off = Outbox::default();
        handed_off
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();
        handed_off.reserve(&bob(), &payload).unwrap();
        let mut state = handed_off.encode_state().unwrap();
        assert_eq!(Outbox::decode_state(&state), Ok(handed_off));
        // Handed off with the final attempt's count would be exhausted.
        assert_eq!(
            decode_after_patching(&mut state, attempts_from_end, 3),
            Err(GroupError::Malformed)
        );

        let mut exhausted = Outbox::default();
        exhausted
            .record_prepared(bob(), payload.clone(), vec![7, 8])
            .unwrap();
        for _ in 0..3 {
            exhausted.reserve(&bob(), &payload).unwrap();
        }
        let mut state = exhausted.encode_state().unwrap();
        assert_eq!(Outbox::decode_state(&state), Ok(exhausted));
        // Exhausted before three attempts were reserved cannot have happened.
        assert_eq!(
            decode_after_patching(&mut state, attempts_from_end, 2),
            Err(GroupError::Malformed)
        );
    }

    #[test]
    fn the_entry_bounds_hold_on_encode_and_on_decode() {
        let roster = |revision: u64| {
            GroupPayload::Roster(
                Roster::new(
                    GroupId::new(*b"bounded-group-id"),
                    revision,
                    [0; DIGEST_LEN],
                    alice(),
                    POLICY_VERSION_V1,
                    false,
                    vec![alice(), bob()],
                )
                .unwrap(),
            )
            .encode()
            .unwrap()
        };
        // Nine live handoffs cannot be recorded, and cannot be encoded either.
        let mut outbox = Outbox::default();
        for revision in 1..=8 {
            outbox
                .record_prepared(bob(), roster(revision), vec![revision as u8])
                .unwrap();
        }
        let mut over = outbox.clone();
        over.handoffs.push(Handoff {
            recipient: bob(),
            payload: roster(9),
            ciphertext: vec![9],
            attempts_reserved: 0,
            disposition: Disposition::Prepared,
            sequence: 9,
        });
        assert_eq!(over.encode_state(), Err(GroupError::OutboxFull));
        // Seventeen terminal handoffs cannot be encoded.
        let mut terminal = Outbox::default();
        for revision in 1..=17u64 {
            terminal.handoffs.push(Handoff {
                recipient: bob(),
                payload: roster(revision),
                ciphertext: vec![revision as u8],
                attempts_reserved: 1,
                disposition: Disposition::RelayAccepted,
                sequence: revision,
            });
        }
        assert_eq!(terminal.encode_state(), Err(GroupError::OutboxFull));
        // A state that claims more than twenty-four entries is refused before
        // any entry is read.
        let mut claim = DOMAIN.to_vec();
        claim.push(25);
        assert_eq!(Outbox::decode_state(&claim), Err(GroupError::OutboxFull));
        let mut claim = DOMAIN.to_vec();
        claim.push(24);
        assert_eq!(Outbox::decode_state(&claim), Err(GroupError::Malformed));
    }
}
