//! The pure trust core of the directory.
//!
//! The directory binds each device to a public identity key under *trust on
//! first use*: the first registration of a device sticks, and a later one must
//! present the same key (it may refresh the prekey bundle) or be rejected — an
//! address cannot be silently reassigned. Authorized *rotation* replaces the
//! bound key through a separate path.
//!
//! [`tacenta-directory`](../tacenta_directory/index.html)'s `Directory` holds
//! this state in a `HashMap`. A `HashMap` is outside the subset a Rust→Lean
//! refinement (Charon/Aeneas) can translate, and it carries no trust anyway.
//! So the trust *decision* lives here instead, as pure functions of a single
//! device's current binding — [`register_core`] and [`rotate_core`] — with the
//! `HashMap` reduced to glue that stores the result. These two functions are in
//! the translatable subset and are mechanically refined to the Lean spec
//! (`spec/Tacenta/Directory.lean`, `registerCore` / `rotateCore`), so the
//! shipped trust logic — not just a model of it — inherits the trust-on-first-
//! use and rotation theorems. See `docs/decisions/0041`.

/// The outcome of a registration attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    /// The device was unbound; it is now bound to the presented identity.
    Registered,
    /// The device was already bound to this same identity; only the prekey
    /// bundle (held by the caller, not here) refreshes.
    Refreshed,
    /// The device is bound to a *different* identity. Nothing changes — trust
    /// on first use forbids reassigning the binding. An authorized change goes
    /// through rotation instead.
    Rejected,
}

/// The outcome of an authorized identity rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    /// The device was bound; its identity is now replaced.
    Rotated,
    /// The device was not bound — there is no binding to rotate.
    Unregistered,
}

/// The trust-on-first-use decision for a registration, as a pure function of
/// the device's current identity binding.
///
/// Given the identity a device is currently bound to (`None` if unbound) and a
/// presented identity, returns the outcome and the identity the device is bound
/// to afterwards: a fresh device binds the presented key; a bound device that
/// presents the same key refreshes; a bound device that presents a *different*
/// key is rejected and **keeps its existing binding**. All of the directory's
/// trust-on-first-use guarantee is in these three lines; the surrounding
/// `Directory::register` is container glue that stores the bundle and indexes
/// the device.
pub fn register_core(current: Option<Vec<u8>>, presented: Vec<u8>) -> (Registration, Vec<u8>) {
    match current {
        None => (Registration::Registered, presented),
        Some(existing) => {
            if existing == presented {
                (Registration::Refreshed, presented)
            } else {
                (Registration::Rejected, existing)
            }
        }
    }
}

/// The authorized-rotation decision, the sibling of [`register_core`]. A bound
/// device rotates to the new key; an unbound device cannot be rotated and stays
/// unbound. The rotation's *authorization* (a signature the currently-bound key
/// accepts) lives above the store; this is only the crypto-free state rule.
pub fn rotate_core(current: Option<Vec<u8>>, new_identity: Vec<u8>) -> (Rotation, Option<Vec<u8>>) {
    match current {
        None => (Rotation::Unregistered, None),
        Some(_) => (Rotation::Rotated, Some(new_identity)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_core_is_tofu() {
        let k = b"key".to_vec();
        assert_eq!(
            register_core(None, k.clone()),
            (Registration::Registered, k.clone())
        );
        assert_eq!(
            register_core(Some(k.clone()), k.clone()),
            (Registration::Refreshed, k.clone())
        );
        // A different key presented to a bound device is rejected and the
        // existing binding is preserved.
        assert_eq!(
            register_core(Some(k.clone()), b"other".to_vec()),
            (Registration::Rejected, k)
        );
    }

    #[test]
    fn rotate_core_requires_a_binding() {
        let new = b"new".to_vec();
        assert_eq!(
            rotate_core(None, new.clone()),
            (Rotation::Unregistered, None)
        );
        assert_eq!(
            rotate_core(Some(b"old".to_vec()), new.clone()),
            (Rotation::Rotated, Some(new))
        );
    }
}
