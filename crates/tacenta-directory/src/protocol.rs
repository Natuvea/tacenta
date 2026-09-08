//! The directory's request/response protocol: register a device's public
//! material, or look one up. The byte encoding matches the wire style
//! used across the repo (big-endian `u32` length prefixes).
//!
//! Registration carries a `signature` over a server-issued challenge —
//! the registrant's proof that it holds the private key for the identity
//! it submits (decision record 0019). Verifying that signature is
//! cryptographic and does not happen here: this crate stays crypto-free,
//! so the transport verifies possession (via injected crypto) before
//! applying [`Directory::register`], exactly as it verifies a connection's
//! identity before dispatching a relay request. Lookups are public — the
//! material is public key bytes — so they carry no proof.

use crate::{Directory, Registration, Rotation};
use tacenta_relay::DeviceAddr;

/// A client's request to the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirRequest {
    /// Publish `identity` and `bundle` for `device`, with `signature` over
    /// the connection's challenge proving possession of `identity`.
    Register {
        device: DeviceAddr,
        identity: Vec<u8>,
        bundle: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Ask for a device's published identity key and prekey bundle.
    Lookup { device: DeviceAddr },
    /// Stock a device's one-time bundle pool (decision 0074).
    ///
    /// Authenticated exactly as `Register` is, by proving possession of the
    /// identity against the connection's challenge. Anyone may fetch a
    /// bundle; only the device may stock the pool it is served from, or a
    /// third party could feed bundles whose one-time private halves it holds.
    DepositPrekeys {
        device: DeviceAddr,
        identity: Vec<u8>,
        bundles: Vec<Vec<u8>>,
        signature: Vec<u8>,
    },
    /// Rotate `device`'s bound identity to `new_identity` + `new_bundle`.
    /// `possession_sig` is the new key's signature over the challenge;
    /// `rotation_sig` is the *currently bound* key's signature over
    /// `challenge ++ new_identity`, authorizing the change (decision record
    /// 0024).
    Rotate {
        device: DeviceAddr,
        new_identity: Vec<u8>,
        new_bundle: Vec<u8>,
        possession_sig: Vec<u8>,
        rotation_sig: Vec<u8>,
    },
    /// Attach a `recovery` key to `device`, authorized by `signature` from
    /// the currently bound identity key over the challenge (decision record
    /// 0025).
    SetRecovery {
        device: DeviceAddr,
        recovery: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Recover `device` to `new_identity` + `new_bundle` when the identity
    /// key is lost: `possession_sig` is the new key over the challenge, and
    /// `recovery_sig` is the *recovery* key over `challenge ++ new_identity`.
    Recover {
        device: DeviceAddr,
        new_identity: Vec<u8>,
        new_bundle: Vec<u8>,
        possession_sig: Vec<u8>,
        recovery_sig: Vec<u8>,
    },
    /// Present `device`'s current persisted-state `generation` for the directory
    /// to witness (decision 0078). `signature` proves possession over the
    /// challenge; unlike `Register`, no identity is submitted — the server
    /// verifies against the key already bound, so a caller cannot witness under
    /// a key it does not own.
    Witness {
        device: DeviceAddr,
        generation: u64,
        signature: Vec<u8>,
    },
}

/// The directory's response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirResponse {
    /// A registration for a previously unregistered address succeeded.
    Registered,
    /// A registration under the address's existing identity refreshed its
    /// bundle.
    Refreshed,
    /// A registration was refused: the address is bound to a different
    /// identity (trust on first use).
    Rejected,
    /// A registration was refused: the signature did not prove possession
    /// of the submitted identity key.
    PossessionFailed,
    /// The looked-up device's published material.
    Found { identity: Vec<u8>, bundle: Vec<u8> },
    /// The pool was stocked; the value is its new depth, so a client can
    /// decide whether to send more without a second round trip.
    Deposited(u32),
    /// The presented identity is not the one bound to this address.
    DepositRejected,
    /// The looked-up device is not registered.
    NotFound,
    /// A rotation succeeded; the binding now holds the new key.
    Rotated,
    /// A rotation was refused: not authorized by the currently bound key.
    Unauthorized,
    /// A rotation was refused: the address is not registered.
    Unregistered,
    /// A recovery key was attached to the address.
    RecoverySet,
    /// A recover was refused: the address has no recovery key set.
    NoRecovery,
    /// A registration was refused: the handle is in the namespace reserved for
    /// account provisioning.
    ///
    /// **Distinct from `Rejected` on purpose.** `Rejected` means trust on first
    /// use found a different key already bound, which a caller can reason about.
    /// This means the caller may never bind this shape of handle over the
    /// unauthenticated directory path however unclaimed it is, and a developer
    /// who confuses the two will go looking for a phantom existing binding.
    ReservedHandle,
    /// A witnessed generation is at or ahead of the highest the directory has
    /// seen: the presented state is current (decision 0078).
    Fresh,
    /// A witnessed generation is below the highest seen: an older state is
    /// being presented, which is a rollback. The client keeps its identity and
    /// discards its sessions (decision 0078, decision 3).
    RolledBack,
    /// A **new** handle registration was refused because this source has made too
    /// many recently (registration admission control, decision 0079).
    ///
    /// **Transient — retry later.** Unlike `Rejected` (the handle belongs to
    /// another key) or `ReservedHandle` (the caller may never bind it), this says
    /// nothing about the handle or the key; it throttles the *rate* of new
    /// registrations per source. Only new bindings are limited — a re-confirm of a
    /// handle the source already holds is never refused this way. Checked after
    /// possession, so it leaks nothing to a caller who cannot prove the key.
    RateLimited,
    /// A **new** raw-handle registration was refused because the deployment runs
    /// `AccountsOnly`: unauthenticated self-registration is closed, and handles are
    /// obtained through authenticated account provisioning instead (layer 2,
    /// decision 0080).
    ///
    /// **Permanent for this path, unlike `RateLimited`.** Retrying the same
    /// unauthenticated registration cannot succeed; the caller must provision
    /// through an account. A re-confirm of a handle the caller already holds is
    /// *not* refused this way.
    RegistrationClosed,
}

impl From<Registration> for DirResponse {
    fn from(outcome: Registration) -> DirResponse {
        match outcome {
            Registration::Registered => DirResponse::Registered,
            Registration::Refreshed => DirResponse::Refreshed,
            Registration::Rejected => DirResponse::Rejected,
        }
    }
}

impl From<Rotation> for DirResponse {
    fn from(outcome: Rotation) -> DirResponse {
        match outcome {
            Rotation::Rotated => DirResponse::Rotated,
            Rotation::Unregistered => DirResponse::Unregistered,
        }
    }
}

impl From<crate::Deposit> for DirResponse {
    fn from(outcome: crate::Deposit) -> DirResponse {
        match outcome {
            crate::Deposit::Deposited(depth) => {
                DirResponse::Deposited(u32::try_from(depth).unwrap_or(u32::MAX))
            }
            crate::Deposit::Rejected => DirResponse::DepositRejected,
            crate::Deposit::Unregistered => DirResponse::Unregistered,
        }
    }
}

impl From<crate::RecoverySet> for DirResponse {
    fn from(outcome: crate::RecoverySet) -> DirResponse {
        match outcome {
            crate::RecoverySet::Set => DirResponse::RecoverySet,
            crate::RecoverySet::Unregistered => DirResponse::Unregistered,
        }
    }
}

impl From<crate::Witness> for DirResponse {
    fn from(outcome: crate::Witness) -> DirResponse {
        match outcome {
            crate::Witness::Fresh => DirResponse::Fresh,
            crate::Witness::RolledBack => DirResponse::RolledBack,
            crate::Witness::Unregistered => DirResponse::Unregistered,
        }
    }
}

impl Directory {
    /// A device's published identity key and a prekey bundle together, for a
    /// `Lookup`. `None` if the device is not registered.
    ///
    /// **Dispensing, and therefore `&mut self`.** This is the peer-facing
    /// path, so it consumes a one-time bundle when one is available; that is
    /// the whole of decision 0074 and the reason a lookup now has an effect.
    /// The directory still holds only public material and still cannot read a
    /// message, but it has stopped being stateless, amending decision 0018.
    pub fn lookup(&mut self, device: &DeviceAddr) -> Option<(Vec<u8>, Vec<u8>)> {
        let identity = self.identity(device)?.to_vec();
        let bundle = self.take_bundle(device)?;
        Some((identity, bundle))
    }
}

/// Big-endian `u32` value (a count, not a length prefix). Shared with the
/// snapshot codec in `persist`.
pub(crate) fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

pub(crate) fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_be_bytes(head.try_into().ok()?), rest))
}

/// Big-endian `u32` length prefix, then the block.
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).expect("block fits u32"));
    out.extend_from_slice(bytes);
}

pub(crate) fn take_bytes(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = take_u32(bytes)?;
    rest.split_at_checked(len as usize)
}

pub(crate) fn put_addr(out: &mut Vec<u8>, addr: &DeviceAddr) {
    put_bytes(out, addr.user.as_bytes());
    put_u32(out, addr.device);
}

pub(crate) fn take_addr(bytes: &[u8]) -> Option<(DeviceAddr, &[u8])> {
    let (user_bytes, rest) = take_bytes(bytes)?;
    let user = String::from_utf8(user_bytes.to_vec()).ok()?;
    let (device, rest) = take_u32(rest)?;
    Some((DeviceAddr { user, device }, rest))
}

/// Encode a request. Tags: 1 = Register, 2 = Lookup, 3 = Rotate.
pub fn encode_dir_request(request: &DirRequest) -> Vec<u8> {
    let mut out = Vec::new();
    match request {
        DirRequest::Register {
            device,
            identity,
            bundle,
            signature,
        } => {
            out.push(1);
            put_addr(&mut out, device);
            put_bytes(&mut out, identity);
            put_bytes(&mut out, bundle);
            put_bytes(&mut out, signature);
        }
        DirRequest::Lookup { device } => {
            out.push(2);
            put_addr(&mut out, device);
        }
        DirRequest::Rotate {
            device,
            new_identity,
            new_bundle,
            possession_sig,
            rotation_sig,
        } => {
            out.push(3);
            put_addr(&mut out, device);
            put_bytes(&mut out, new_identity);
            put_bytes(&mut out, new_bundle);
            put_bytes(&mut out, possession_sig);
            put_bytes(&mut out, rotation_sig);
        }
        DirRequest::SetRecovery {
            device,
            recovery,
            signature,
        } => {
            out.push(4);
            put_addr(&mut out, device);
            put_bytes(&mut out, recovery);
            put_bytes(&mut out, signature);
        }
        DirRequest::Recover {
            device,
            new_identity,
            new_bundle,
            possession_sig,
            recovery_sig,
        } => {
            out.push(5);
            put_addr(&mut out, device);
            put_bytes(&mut out, new_identity);
            put_bytes(&mut out, new_bundle);
            put_bytes(&mut out, possession_sig);
            put_bytes(&mut out, recovery_sig);
        }
        DirRequest::DepositPrekeys {
            device,
            identity,
            bundles,
            signature,
        } => {
            out.push(6);
            put_addr(&mut out, device);
            put_bytes(&mut out, identity);
            put_u32(
                &mut out,
                u32::try_from(bundles.len()).expect("batch size fits u32"),
            );
            for bundle in bundles {
                put_bytes(&mut out, bundle);
            }
            put_bytes(&mut out, signature);
        }
        DirRequest::Witness {
            device,
            generation,
            signature,
        } => {
            out.push(7);
            put_addr(&mut out, device);
            out.extend_from_slice(&generation.to_be_bytes());
            put_bytes(&mut out, signature);
        }
    }
    out
}

/// Decode a request; `None` on any malformation.
pub fn decode_dir_request(bytes: &[u8]) -> Option<DirRequest> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => {
            let (device, rest) = take_addr(rest)?;
            let (identity, rest) = take_bytes(rest)?;
            let (bundle, rest) = take_bytes(rest)?;
            let (signature, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirRequest::Register {
                device,
                identity: identity.to_vec(),
                bundle: bundle.to_vec(),
                signature: signature.to_vec(),
            })
        }
        2 => {
            let (device, rest) = take_addr(rest)?;
            rest.is_empty().then_some(DirRequest::Lookup { device })
        }
        3 => {
            let (device, rest) = take_addr(rest)?;
            let (new_identity, rest) = take_bytes(rest)?;
            let (new_bundle, rest) = take_bytes(rest)?;
            let (possession_sig, rest) = take_bytes(rest)?;
            let (rotation_sig, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirRequest::Rotate {
                device,
                new_identity: new_identity.to_vec(),
                new_bundle: new_bundle.to_vec(),
                possession_sig: possession_sig.to_vec(),
                rotation_sig: rotation_sig.to_vec(),
            })
        }
        4 => {
            let (device, rest) = take_addr(rest)?;
            let (recovery, rest) = take_bytes(rest)?;
            let (signature, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirRequest::SetRecovery {
                device,
                recovery: recovery.to_vec(),
                signature: signature.to_vec(),
            })
        }
        5 => {
            let (device, rest) = take_addr(rest)?;
            let (new_identity, rest) = take_bytes(rest)?;
            let (new_bundle, rest) = take_bytes(rest)?;
            let (possession_sig, rest) = take_bytes(rest)?;
            let (recovery_sig, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirRequest::Recover {
                device,
                new_identity: new_identity.to_vec(),
                new_bundle: new_bundle.to_vec(),
                possession_sig: possession_sig.to_vec(),
                recovery_sig: recovery_sig.to_vec(),
            })
        }
        6 => {
            let (device, rest) = take_addr(rest)?;
            let (identity, rest) = take_bytes(rest)?;
            let (count, mut rest) = take_u32(rest)?;
            // A count is not a length: it is read off the wire and must not
            // be trusted to size an allocation before the bytes behind it
            // have been seen. Pushed one at a time, so a lying count runs out
            // of input and fails instead of reserving gigabytes first.
            let mut bundles = Vec::new();
            for _ in 0..count {
                let (bundle, next) = take_bytes(rest)?;
                bundles.push(bundle.to_vec());
                rest = next;
            }
            let (signature, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirRequest::DepositPrekeys {
                device,
                identity: identity.to_vec(),
                bundles,
                signature: signature.to_vec(),
            })
        }
        7 => {
            let (device, rest) = take_addr(rest)?;
            let (gen_bytes, rest) = rest.split_at_checked(8)?;
            let generation = u64::from_be_bytes(gen_bytes.try_into().ok()?);
            let (signature, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirRequest::Witness {
                device,
                generation,
                signature: signature.to_vec(),
            })
        }
        _ => None,
    }
}

/// Encode a response. Tags: 1 = Registered, 2 = Refreshed, 3 = Rejected,
/// 4 = PossessionFailed, 5 = Found, 6 = NotFound, 7 = Rotated,
/// 8 = Unauthorized, 9 = Unregistered, 10 = RecoverySet, 11 = NoRecovery,
/// 12 = Deposited, 13 = DepositRejected.
pub fn encode_dir_response(response: &DirResponse) -> Vec<u8> {
    let mut out = Vec::new();
    match response {
        DirResponse::Registered => out.push(1),
        DirResponse::Refreshed => out.push(2),
        DirResponse::Rejected => out.push(3),
        DirResponse::PossessionFailed => out.push(4),
        DirResponse::Found { identity, bundle } => {
            out.push(5);
            put_bytes(&mut out, identity);
            put_bytes(&mut out, bundle);
        }
        DirResponse::NotFound => out.push(6),
        DirResponse::Rotated => out.push(7),
        DirResponse::Unauthorized => out.push(8),
        DirResponse::Unregistered => out.push(9),
        DirResponse::RecoverySet => out.push(10),
        DirResponse::NoRecovery => out.push(11),
        DirResponse::Deposited(depth) => {
            out.push(12);
            put_u32(&mut out, *depth);
        }
        DirResponse::DepositRejected => out.push(13),
        DirResponse::ReservedHandle => out.push(14),
        DirResponse::Fresh => out.push(15),
        DirResponse::RolledBack => out.push(16),
        DirResponse::RateLimited => out.push(17),
        DirResponse::RegistrationClosed => out.push(18),
    }
    out
}

/// Decode a response; `None` on any malformation.
pub fn decode_dir_response(bytes: &[u8]) -> Option<DirResponse> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => rest.is_empty().then_some(DirResponse::Registered),
        2 => rest.is_empty().then_some(DirResponse::Refreshed),
        3 => rest.is_empty().then_some(DirResponse::Rejected),
        4 => rest.is_empty().then_some(DirResponse::PossessionFailed),
        5 => {
            let (identity, rest) = take_bytes(rest)?;
            let (bundle, rest) = take_bytes(rest)?;
            rest.is_empty().then(|| DirResponse::Found {
                identity: identity.to_vec(),
                bundle: bundle.to_vec(),
            })
        }
        6 => rest.is_empty().then_some(DirResponse::NotFound),
        7 => rest.is_empty().then_some(DirResponse::Rotated),
        8 => rest.is_empty().then_some(DirResponse::Unauthorized),
        9 => rest.is_empty().then_some(DirResponse::Unregistered),
        10 => rest.is_empty().then_some(DirResponse::RecoverySet),
        11 => rest.is_empty().then_some(DirResponse::NoRecovery),
        12 => {
            let (depth, rest) = take_u32(rest)?;
            rest.is_empty().then_some(DirResponse::Deposited(depth))
        }
        13 => rest.is_empty().then_some(DirResponse::DepositRejected),
        14 => rest.is_empty().then_some(DirResponse::ReservedHandle),
        15 => rest.is_empty().then_some(DirResponse::Fresh),
        16 => rest.is_empty().then_some(DirResponse::RolledBack),
        17 => rest.is_empty().then_some(DirResponse::RateLimited),
        18 => rest.is_empty().then_some(DirResponse::RegistrationClosed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> DeviceAddr {
        DeviceAddr::new("+alice", 3)
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            DirRequest::Register {
                device: addr(),
                identity: b"id".to_vec(),
                bundle: b"bundle".to_vec(),
                signature: b"sig".to_vec(),
            },
            DirRequest::Lookup { device: addr() },
            DirRequest::Rotate {
                device: addr(),
                new_identity: b"new-id".to_vec(),
                new_bundle: b"new-bundle".to_vec(),
                possession_sig: b"psig".to_vec(),
                rotation_sig: b"rsig".to_vec(),
            },
            DirRequest::SetRecovery {
                device: addr(),
                recovery: b"recovery-key".to_vec(),
                signature: b"sig".to_vec(),
            },
            DirRequest::Recover {
                device: addr(),
                new_identity: b"new-id".to_vec(),
                new_bundle: b"new-bundle".to_vec(),
                possession_sig: b"psig".to_vec(),
                recovery_sig: b"rsig".to_vec(),
            },
            DirRequest::Witness {
                device: addr(),
                generation: 0x0102_0304_0506_0708,
                signature: b"sig".to_vec(),
            },
        ] {
            assert_eq!(decode_dir_request(&encode_dir_request(&r)), Some(r));
        }
    }

    #[test]
    fn responses_round_trip() {
        for r in [
            DirResponse::Registered,
            DirResponse::Refreshed,
            DirResponse::Rejected,
            DirResponse::PossessionFailed,
            DirResponse::Found {
                identity: b"id".to_vec(),
                bundle: b"bundle".to_vec(),
            },
            DirResponse::NotFound,
            DirResponse::Rotated,
            DirResponse::Unauthorized,
            DirResponse::Unregistered,
            DirResponse::RecoverySet,
            DirResponse::NoRecovery,
            DirResponse::ReservedHandle,
            DirResponse::Fresh,
            DirResponse::RolledBack,
            DirResponse::RateLimited,
            DirResponse::RegistrationClosed,
        ] {
            assert_eq!(decode_dir_response(&encode_dir_response(&r)), Some(r));
        }
    }

    #[test]
    fn malformed_is_rejected() {
        assert_eq!(decode_dir_request(&[]), None);
        assert_eq!(decode_dir_request(&[9]), None);
        assert_eq!(decode_dir_request(&[2, 0, 0, 0, 255]), None); // truncated addr
        assert_eq!(decode_dir_request(&[12]), None); // unknown request tag
        assert_eq!(decode_dir_response(&[12]), None); // unknown response tag
        assert_eq!(decode_dir_response(&[1, 0]), None); // trailing junk
    }

    #[test]
    fn lookup_returns_both_or_nothing() {
        let mut dir = Directory::new();
        let a = addr();
        assert_eq!(dir.lookup(&a), None);
        dir.register(&a, b"id".to_vec(), b"bundle".to_vec());
        assert_eq!(dir.lookup(&a), Some((b"id".to_vec(), b"bundle".to_vec())));
    }
}
