//! Whole-state snapshot and restore for the account store, so tenants, users,
//! API keys, and sessions survive a server restart — the same
//! snapshot-on-shutdown / load-on-start posture the directory and relay use
//! (decision record 0022), until the durable store (decision record 0030)
//! replaces all three snapshots at once.
//!
//! The bytes carry password hashes (argon2id) and the SHA-256 digests of API
//! keys and session tokens — never a plaintext secret, but still sensitive at
//! rest, exactly as the directory snapshot carries identity keys.
//!
//! Only the authoritative records and the two hash-keyed indexes (API keys,
//! sessions) are stored; the tenant username/email lookup indexes are rebuilt
//! on restore, so they cannot drift from the records.
//!
//! # Two shapes, and why a cut cannot pass for either
//!
//! Servers before hosted device inventories wrote four sections (tenants, API
//! keys, users, sessions) and nothing else, with no header. That shape is still
//! read, and it must end exactly after the sessions, so an upgrade keeps its
//! accounts.
//!
//! From then on a snapshot starts with [`SNAPSHOT_HEADER`] and holds those four
//! sections and then three more (device inventories, link retry records,
//! lifecycle retry records), every one of them present even when empty. If the
//! trailing sections were optional, a copy cut right after the sessions would
//! be byte for byte the old shape and would restore with every device
//! inventory reset to generation zero and every revocation undone. The header
//! is what tells the two apart: with it, a snapshot that ends at any section
//! boundary is refused as [`RestoreError::Truncated`].

use crate::protocol::{put_str, put_u32, put_u64, take_str, take_u32, take_u64};
use tacenta_core::crypto::groups::inventory::{
    DeviceBinding, MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS, Revocation,
};

use crate::{
    Accounts, ApiKeyRecord, DeviceInventory, TenantId, TenantRecord, UserRecord,
    inventory::{encode_inventory, validate_inventory},
};

/// The first eight bytes of every snapshot written since hosted device
/// inventories: `ffffffff` then `TCA2`.
///
/// The earlier shape begins with a big-endian count of tenants. `ffffffff`
/// tenants would take at least 16 bytes each, 64 GiB, so no earlier snapshot
/// starts with these four bytes, and a reader can tell the two shapes apart from
/// the first bytes alone.
pub(crate) const SNAPSHOT_HEADER: [u8; 8] = *b"\xff\xff\xff\xffTCA2";

/// A part of a snapshot, in the order it is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnapshotSection {
    /// The eight-byte [`SNAPSHOT_HEADER`].
    Header,
    Tenants,
    ApiKeys,
    Users,
    Sessions,
    /// Every account's device inventory.
    Inventories,
    /// The retry records of device links.
    LinkRecords,
    /// The retry records of device replacements and revocations.
    LifecycleRecords,
}

/// Why [`Accounts::try_restore`] refused a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// The bytes are not a snapshot: a record is cut short or malformed, a count
    /// is impossible, or bytes follow the last section.
    Malformed,
    /// The snapshot ends cleanly at the end of `after`, and a section that must
    /// follow it is missing. It is a copy that was cut, or is still being
    /// written, and restoring it would silently drop everything after the cut.
    Truncated { after: SnapshotSection },
    /// A record in `section` names a tenant or a user the snapshot does not hold.
    Orphan { section: SnapshotSection },
    /// A record in `section` is well formed and breaks a rule of the store: an
    /// inventory the core would not encode, a repeated record, or a retry record
    /// whose result does not follow its predecessor.
    Inconsistent { section: SnapshotSection },
}

fn put_hash(out: &mut Vec<u8>, hash: &[u8; 32]) {
    out.extend_from_slice(hash);
}

fn take_hash(bytes: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (head, rest) = bytes.split_at_checked(32)?;
    Some((head.try_into().ok()?, rest))
}

fn put_binding(out: &mut Vec<u8>, binding: &DeviceBinding) {
    put_u32(out, binding.device_id);
    out.extend_from_slice(&binding.identity_public_key);
    put_u64(out, binding.capabilities);
    match binding.replacement_predecessor {
        Some(predecessor) => {
            out.push(1);
            out.extend_from_slice(&predecessor);
        }
        None => out.push(0),
    }
}

fn take_binding(bytes: &[u8]) -> Option<(DeviceBinding, &[u8])> {
    let (device_id, rest) = take_u32(bytes)?;
    let (identity_public_key, rest) = take_hash(rest)?;
    let (capabilities, rest) = take_u64(rest)?;
    let (present, rest) = rest.split_first()?;
    let (replacement_predecessor, rest) = match present {
        0 => (None, rest),
        1 => {
            let (key, rest) = take_hash(rest)?;
            (Some(key), rest)
        }
        _ => return None,
    };
    Some((
        DeviceBinding {
            device_id,
            identity_public_key,
            capabilities,
            replacement_predecessor,
        },
        rest,
    ))
}

fn put_inventory(out: &mut Vec<u8>, inventory: &DeviceInventory) {
    out.extend_from_slice(&encode_inventory(inventory));
}

fn take_inventory(bytes: &[u8]) -> Option<(DeviceInventory, &[u8])> {
    let (generation, mut rest) = take_u64(bytes)?;
    let (active_count, r) = take_u32(rest)?;
    if active_count as usize > MAX_ACTIVE_BINDINGS {
        return None;
    }
    rest = r;
    let mut active = Vec::new();
    for _ in 0..active_count {
        let (binding, r) = take_binding(rest)?;
        active.push(binding);
        rest = r;
    }
    let (revocation_floor_generation, r) = take_u64(rest)?;
    rest = r;
    let (revoked_count, r) = take_u32(rest)?;
    if revoked_count as usize > MAX_RECENT_REVOCATIONS {
        return None;
    }
    rest = r;
    let mut revoked = Vec::new();
    for _ in 0..revoked_count {
        let (binding, r) = take_binding(rest)?;
        let (terminal_generation, r) = take_u64(r)?;
        revoked.push(Revocation {
            binding,
            terminal_generation,
        });
        rest = r;
    }
    Some((
        DeviceInventory {
            generation,
            active,
            revocation_floor_generation,
            revoked,
        },
        rest,
    ))
}

fn put_lifecycle_request(out: &mut Vec<u8>, request: &crate::inventory::LifecycleRequest) {
    match request {
        crate::inventory::LifecycleRequest::Replace {
            predecessor_generation,
            retired,
            replacement,
        } => {
            out.push(1);
            put_u64(out, *predecessor_generation);
            put_binding(out, retired);
            put_binding(out, replacement);
        }
        crate::inventory::LifecycleRequest::Revoke {
            predecessor_generation,
            retired,
        } => {
            out.push(2);
            put_u64(out, *predecessor_generation);
            put_binding(out, retired);
        }
    }
}

fn take_lifecycle_request(bytes: &[u8]) -> Option<(crate::inventory::LifecycleRequest, &[u8])> {
    let (tag, rest) = bytes.split_first()?;
    let (predecessor_generation, rest) = take_u64(rest)?;
    match tag {
        1 => {
            let (retired, rest) = take_binding(rest)?;
            let (replacement, rest) = take_binding(rest)?;
            Some((
                crate::inventory::LifecycleRequest::Replace {
                    predecessor_generation,
                    retired,
                    replacement,
                },
                rest,
            ))
        }
        2 => {
            let (retired, rest) = take_binding(rest)?;
            Some((
                crate::inventory::LifecycleRequest::Revoke {
                    predecessor_generation,
                    retired,
                },
                rest,
            ))
        }
        _ => None,
    }
}

impl Accounts {
    /// Serialize the whole store to bytes a caller can persist and later hand
    /// to [`restore`](Accounts::restore).
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = SNAPSHOT_HEADER.to_vec();

        put_u32(&mut out, self.tenants.len() as u32);
        for tenant in self.tenants.values() {
            put_str(&mut out, tenant.id.as_str());
            put_str(&mut out, &tenant.username);
            put_str(&mut out, &tenant.email);
            put_str(&mut out, &tenant.password_hash);
        }

        put_u32(&mut out, self.api_keys.len() as u32);
        for (hash, record) in &self.api_keys {
            put_hash(&mut out, hash);
            put_str(&mut out, record.tenant.as_str());
            put_str(&mut out, &record.prefix);
            // Empty string encodes "no label"; a real label is never empty.
            put_str(&mut out, record.label.as_deref().unwrap_or(""));
            put_u64(&mut out, record.created_at);
        }

        put_u32(&mut out, self.users.len() as u32);
        for user in self.users.values() {
            put_str(&mut out, user.tenant.as_str());
            put_str(&mut out, &user.username);
            put_str(&mut out, &user.password_hash);
        }

        put_u32(&mut out, self.sessions.len() as u32);
        for (hash, (tenant, username, expires_at)) in &self.sessions {
            put_hash(&mut out, hash);
            put_str(&mut out, tenant.as_str());
            put_str(&mut out, username);
            put_u64(&mut out, *expires_at);
        }

        put_u32(&mut out, self.device_inventories.len() as u32);
        for ((tenant, username), inventory) in &self.device_inventories {
            put_str(&mut out, tenant.as_str());
            put_str(&mut out, username);
            put_inventory(&mut out, inventory);
        }
        put_u32(&mut out, self.inventory_mutations.len() as u32);
        for ((tenant, username, idempotency_key), mutation) in &self.inventory_mutations {
            put_str(&mut out, tenant.as_str());
            put_str(&mut out, username);
            out.extend_from_slice(idempotency_key);
            put_u64(&mut out, mutation.predecessor_generation);
            put_binding(&mut out, &mutation.binding);
            put_inventory(&mut out, &mutation.result);
        }
        put_u32(&mut out, self.inventory_lifecycle_mutations.len() as u32);
        for ((tenant, username, idempotency_key), mutation) in &self.inventory_lifecycle_mutations {
            put_str(&mut out, tenant.as_str());
            put_str(&mut out, username);
            out.extend_from_slice(idempotency_key);
            put_lifecycle_request(&mut out, &mutation.request);
            put_inventory(&mut out, &mutation.result);
        }

        out
    }

    /// Reconstruct a store from [`snapshot`](Accounts::snapshot) bytes; `None`
    /// on any malformation. See [`try_restore`](Accounts::try_restore) for the
    /// reason a snapshot is refused.
    pub fn restore(bytes: &[u8]) -> Option<Accounts> {
        Accounts::try_restore(bytes).ok()
    }

    /// Reconstruct a store from [`snapshot`](Accounts::snapshot) bytes, or say
    /// why not. The tenant username/email indexes are rebuilt from the records.
    ///
    /// A snapshot is refused, and nothing is restored from it, when it is cut
    /// short at any point, including exactly between two sections
    /// ([`RestoreError::Truncated`]); when a user, API key or session names a
    /// tenant or user the snapshot does not hold ([`RestoreError::Orphan`]); or
    /// when a record breaks a rule of the store ([`RestoreError::Inconsistent`]).
    /// The shape that has no header is read only as the four sections older
    /// servers wrote.
    pub fn try_restore(bytes: &[u8]) -> Result<Accounts, RestoreError> {
        use RestoreError::{Inconsistent, Malformed, Orphan, Truncated};
        use SnapshotSection as S;

        fn need<T>(value: Option<T>) -> Result<T, RestoreError> {
            value.ok_or(Malformed)
        }

        let mut accounts = Accounts::new();
        let (headed, mut rest) = match bytes.strip_prefix(&SNAPSHOT_HEADER) {
            Some(rest) => (true, rest),
            None => (false, bytes),
        };
        // The start of a section that must exist. Input that ends here ended
        // between two sections.
        let present = |rest: &[u8], after: SnapshotSection| {
            if rest.is_empty() {
                Err(Truncated { after })
            } else {
                Ok(())
            }
        };

        if headed {
            present(rest, S::Header)?;
        }
        let (tenants, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..tenants {
            let (id, r) = need(take_str(rest))?;
            let (username, r) = need(take_str(r))?;
            let (email, r) = need(take_str(r))?;
            let (password_hash, r) = need(take_str(r))?;
            rest = r;
            let id = TenantId(id);
            accounts
                .tenant_by_username
                .insert(username.clone(), id.clone());
            accounts.tenant_by_email.insert(email.clone(), id.clone());
            accounts.tenants.insert(
                id.clone(),
                TenantRecord {
                    id,
                    username,
                    email,
                    password_hash,
                },
            );
        }

        present(rest, S::Tenants)?;
        let (api_keys, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..api_keys {
            let (hash, r) = need(take_hash(rest))?;
            let (tenant, r) = need(take_str(r))?;
            let (prefix, r) = need(take_str(r))?;
            let (label, r) = need(take_str(r))?;
            let (created_at, r) = need(take_u64(r))?;
            rest = r;
            let tenant = TenantId(tenant);
            if !accounts.tenants.contains_key(&tenant) {
                return Err(Orphan {
                    section: S::ApiKeys,
                });
            }
            accounts.api_keys.insert(
                hash,
                ApiKeyRecord {
                    tenant,
                    prefix,
                    label: (!label.is_empty()).then_some(label),
                    created_at,
                },
            );
        }

        present(rest, S::ApiKeys)?;
        let (users, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..users {
            let (tenant, r) = need(take_str(rest))?;
            let (username, r) = need(take_str(r))?;
            let (password_hash, r) = need(take_str(r))?;
            rest = r;
            let tenant = TenantId(tenant);
            // A user without its tenant has no directory handle. The inventory
            // rules need one, so such a snapshot is refused here rather than
            // tripping them later.
            if !accounts.tenants.contains_key(&tenant) {
                return Err(Orphan { section: S::Users });
            }
            accounts.users.insert(
                (tenant.clone(), username.clone()),
                UserRecord {
                    tenant,
                    username,
                    password_hash,
                },
            );
        }

        present(rest, S::Users)?;
        let (sessions, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..sessions {
            let (hash, r) = need(take_hash(rest))?;
            let (tenant, r) = need(take_str(r))?;
            let (username, r) = need(take_str(r))?;
            let (expires_at, r) = need(take_u64(r))?;
            rest = r;
            let tenant = TenantId(tenant);
            if !accounts
                .users
                .contains_key(&(tenant.clone(), username.clone()))
            {
                return Err(Orphan {
                    section: S::Sessions,
                });
            }
            accounts
                .sessions
                .insert(hash, (tenant, username, expires_at));
        }

        if !headed {
            // The shape older servers wrote ends here, with no device state.
            return if rest.is_empty() {
                Ok(accounts)
            } else {
                Err(Malformed)
            };
        }

        present(rest, S::Sessions)?;
        let (inventories, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..inventories {
            let (tenant, r) = need(take_str(rest))?;
            let (username, r) = need(take_str(r))?;
            let (inventory, r) = need(take_inventory(r))?;
            rest = r;
            let tenant = TenantId(tenant);
            let key = (tenant.clone(), username.clone());
            if !accounts.users.contains_key(&key) {
                return Err(Orphan {
                    section: S::Inventories,
                });
            }
            let handle = accounts.handle(&tenant, &username).ok_or(Orphan {
                section: S::Inventories,
            })?;
            let inconsistent = Inconsistent {
                section: S::Inventories,
            };
            validate_inventory(&handle, &inventory).map_err(|_| inconsistent)?;
            if accounts.device_inventories.insert(key, inventory).is_some() {
                return Err(inconsistent);
            }
        }

        present(rest, S::Inventories)?;
        let (mutations, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..mutations {
            let (tenant, r) = need(take_str(rest))?;
            let (username, r) = need(take_str(r))?;
            let (idempotency_key, r) = need(take_hash(r))?;
            let (predecessor_generation, r) = need(take_u64(r))?;
            let (binding, r) = need(take_binding(r))?;
            let (result, r) = need(take_inventory(r))?;
            rest = r;
            let tenant = TenantId(tenant);
            let account_key = (tenant.clone(), username.clone());
            if !accounts.users.contains_key(&account_key) {
                return Err(Orphan {
                    section: S::LinkRecords,
                });
            }
            let handle = accounts.handle(&tenant, &username).ok_or(Orphan {
                section: S::LinkRecords,
            })?;
            let inconsistent = Inconsistent {
                section: S::LinkRecords,
            };
            validate_inventory(&handle, &result).map_err(|_| inconsistent)?;
            if result.generation <= predecessor_generation {
                return Err(inconsistent);
            }
            let key = (tenant, username, idempotency_key);
            if accounts
                .inventory_mutations
                .insert(
                    key,
                    crate::inventory::InventoryMutation {
                        predecessor_generation,
                        binding,
                        result,
                    },
                )
                .is_some()
            {
                return Err(inconsistent);
            }
        }

        // Replace and revoke retries were appended after the link records, and
        // are as required as the sections before them.
        present(rest, S::LinkRecords)?;
        let (mutations, r) = need(take_u32(rest))?;
        rest = r;
        for _ in 0..mutations {
            let (tenant, r) = need(take_str(rest))?;
            let (username, r) = need(take_str(r))?;
            let (idempotency_key, r) = need(take_hash(r))?;
            let (request, r) = need(take_lifecycle_request(r))?;
            let (result, r) = need(take_inventory(r))?;
            rest = r;
            let tenant = TenantId(tenant);
            let account_key = (tenant.clone(), username.clone());
            if !accounts.users.contains_key(&account_key) {
                return Err(Orphan {
                    section: S::LifecycleRecords,
                });
            }
            let handle = accounts.handle(&tenant, &username).ok_or(Orphan {
                section: S::LifecycleRecords,
            })?;
            let inconsistent = Inconsistent {
                section: S::LifecycleRecords,
            };
            validate_inventory(&handle, &result).map_err(|_| inconsistent)?;
            let predecessor_generation = match &request {
                crate::inventory::LifecycleRequest::Replace {
                    predecessor_generation,
                    ..
                }
                | crate::inventory::LifecycleRequest::Revoke {
                    predecessor_generation,
                    ..
                } => *predecessor_generation,
            };
            if result.generation <= predecessor_generation {
                return Err(inconsistent);
            }
            let key = (tenant, username, idempotency_key);
            if accounts.inventory_mutations.contains_key(&key) {
                return Err(inconsistent);
            }
            if accounts
                .inventory_lifecycle_mutations
                .insert(key, crate::inventory::LifecycleMutation { request, result })
                .is_some()
            {
                return Err(inconsistent);
            }
        }

        if rest.is_empty() {
            Ok(accounts)
        } else {
            Err(Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RestoreError, SNAPSHOT_HEADER, SnapshotSection as S};
    use crate::inventory_rules_tests::honest_key;
    use crate::protocol::{put_str, put_u32, put_u64};
    use crate::{
        AccountStore, Accounts, DeviceInventory, InventoryError, StoreError, TenantId, UserRecord,
    };
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tacenta_core::crypto::groups::inventory::{
        DeviceBinding, GROUP_EPOCH_V1, binding_commitment,
    };

    #[test]
    fn a_snapshot_round_trips_tenants_users_keys_and_sessions() {
        let mut a = Accounts::new();
        let (tenant, api_key) = a
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        a.sign_up_user(&tenant.id, "alice", "hunter2!!").unwrap();
        let (_, token) = a.sign_in(&tenant.id, "alice", "hunter2!!").unwrap();

        let restored = Accounts::restore(&a.snapshot()).expect("snapshot restores");

        // The API key still resolves its tenant.
        assert_eq!(
            restored.tenant_by_api_key(api_key.as_str()),
            Some(tenant.id.clone())
        );
        // The user still authenticates, and its handle is intact.
        assert!(
            restored
                .authenticate_user(&tenant.id, "alice", "hunter2!!")
                .is_ok()
        );
        assert_eq!(
            restored.handle(&tenant.id, "alice").as_deref(),
            Some("acme/alice")
        );
        // The session still validates.
        assert_eq!(
            restored.validate_session(token.as_str()),
            Some((tenant.id.clone(), "alice".to_string())),
        );
        // A bogus API key still resolves to nothing after restore.
        assert!(restored.tenant_by_api_key("tct_nope").is_none());
    }

    #[test]
    fn garbage_does_not_restore() {
        assert!(Accounts::restore(&[]).is_none());
        assert!(Accounts::restore(&[0, 0, 0, 1]).is_none()); // claims a tenant, no body
    }

    #[test]
    fn an_inventory_round_trips_with_its_retry_records() {
        let mut a = Accounts::new();
        let (tenant, _) = a
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        a.sign_up_user(&tenant.id, "alice", "hunter2!!").unwrap();
        let binding = DeviceBinding {
            device_id: 1,
            identity_public_key: honest_key(7),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        };
        let inventory = a
            .link_device_binding(&tenant.id, "alice", 0, [1; 32], binding.clone())
            .unwrap();
        let mut restored = Accounts::restore(&a.snapshot()).expect("inventory snapshot restores");
        assert_eq!(
            restored.device_inventory(&tenant.id, "alice"),
            Some(inventory.clone())
        );
        assert_eq!(
            restored
                .link_device_binding(&tenant.id, "alice", 0, [1; 32], binding)
                .unwrap(),
            inventory,
            "the idempotency result survives a restart"
        );
    }

    #[test]
    fn lifecycle_retry_records_survive_a_snapshot_restore() {
        let mut accounts = Accounts::new();
        let (tenant, _) = accounts
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        accounts
            .sign_up_user(&tenant.id, "alice", "hunter2!!")
            .unwrap();
        let retired = DeviceBinding {
            device_id: 1,
            identity_public_key: honest_key(1),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        };
        accounts
            .link_device_binding(&tenant.id, "alice", 0, [1; 32], retired.clone())
            .unwrap();
        let replacement = DeviceBinding {
            device_id: 2,
            identity_public_key: honest_key(2),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: Some(binding_commitment(&retired).unwrap()),
        };
        let result = accounts
            .replace_device_binding(
                &tenant.id,
                "alice",
                1,
                [2; 32],
                retired.clone(),
                replacement.clone(),
            )
            .unwrap();
        let mut restored = Accounts::restore(&accounts.snapshot()).unwrap();
        assert_eq!(
            restored
                .replace_device_binding(&tenant.id, "alice", 1, [2; 32], retired, replacement,)
                .unwrap(),
            result,
            "the committed replacement result remains the exact retry result"
        );
    }

    // -----------------------------------------------------------------------
    // Snapshot framing: what is refused, and what older servers wrote.
    // -----------------------------------------------------------------------

    fn ten_1() -> TenantId {
        TenantId("ten_1".to_owned())
    }

    /// The four sections a server wrote before hosted device inventories, built
    /// by hand and not by [`Accounts::snapshot`]: no header, and nothing after
    /// the sessions. One tenant, one API key, one user, one session.
    fn older_server_snapshot() -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 1);
        for field in ["ten_1", "acme", "admin@acme.example", "tenant-hash"] {
            put_str(&mut out, field);
        }
        put_u32(&mut out, 1);
        out.extend_from_slice(&Sha256::digest(b"tct_older_key"));
        for field in ["ten_1", "tct_olde", ""] {
            put_str(&mut out, field);
        }
        put_u64(&mut out, 5);
        put_u32(&mut out, 1);
        for field in ["ten_1", "alice", "user-hash"] {
            put_str(&mut out, field);
        }
        put_u32(&mut out, 1);
        out.extend_from_slice(&Sha256::digest(b"older-token"));
        for field in ["ten_1", "alice"] {
            put_str(&mut out, field);
        }
        put_u64(&mut out, u64::MAX);
        out
    }

    #[test]
    fn what_older_servers_wrote_still_restores_and_is_rewritten_with_the_header() {
        let restored = Accounts::try_restore(&older_server_snapshot()).expect("older shape");
        assert_eq!(restored.tenant_by_api_key("tct_older_key"), Some(ten_1()));
        assert_eq!(
            restored.validate_session("older-token"),
            Some((ten_1(), "alice".to_owned()))
        );
        assert_eq!(
            restored.device_inventory(&ten_1(), "alice"),
            Some(DeviceInventory::default())
        );
        let rewritten = restored.snapshot();
        assert!(rewritten.starts_with(&SNAPSHOT_HEADER));
        assert!(Accounts::try_restore(&rewritten).is_ok());
    }

    #[test]
    fn the_older_shape_is_read_only_as_the_four_sections_it_had() {
        let older = older_server_snapshot();
        // Any cut of it is refused, including one between two of its sections.
        for cut in 0..older.len() {
            assert!(Accounts::restore(&older[..cut]).is_none(), "cut at {cut}");
        }
        // Bytes after the sessions are not the sections this shape never had:
        // the framing a development build of this branch wrote (an inventory
        // count after the sessions, no header) is refused, not half read.
        let mut with_count = older.clone();
        put_u32(&mut with_count, 0);
        assert_eq!(
            Accounts::try_restore(&with_count).err(),
            Some(RestoreError::Malformed)
        );
        assert!(Accounts::restore(&[]).is_none());
    }

    /// A store that has something in every section: an API key, a session, and
    /// a device linked, replaced and then revoked (an inventory at generation 3,
    /// one link record and two lifecycle records).
    fn store_with_every_section() -> (Accounts, TenantId) {
        let mut a = Accounts::new();
        let (tenant, _) = a
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        a.sign_up_user(&tenant.id, "alice", "hunter2!!").unwrap();
        a.sign_in(&tenant.id, "alice", "hunter2!!").unwrap();
        let device = |device_id: u32, seed: u8, predecessor| DeviceBinding {
            device_id,
            identity_public_key: honest_key(seed),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: predecessor,
        };
        let first = device(1, 1, None);
        a.link_device_binding(&tenant.id, "alice", 0, [1; 32], first.clone())
            .unwrap();
        let second = device(2, 2, Some(binding_commitment(&first).unwrap()));
        a.replace_device_binding(&tenant.id, "alice", 1, [2; 32], first, second.clone())
            .unwrap();
        a.revoke_device_binding(&tenant.id, "alice", 2, [3; 32], second)
            .unwrap();
        assert_eq!(
            a.device_inventory(&tenant.id, "alice").unwrap().generation,
            3
        );
        (a, tenant.id)
    }

    /// No proper prefix of a snapshot restores, and each section boundary is
    /// named. A copy cut where a section ends must not read as a smaller store:
    /// cut after the sessions it would restore with every device inventory back
    /// at generation zero and every revocation undone, and cut after the
    /// inventories it would have lost every retry record.
    #[test]
    fn a_snapshot_cut_anywhere_is_refused_and_each_section_boundary_is_named() {
        let (accounts, _) = store_with_every_section();
        let full = accounts.snapshot();
        assert!(Accounts::restore(&full).is_some());
        for cut in 0..full.len() {
            assert!(
                Accounts::restore(&full[..cut]).is_none(),
                "a snapshot cut at {cut} of {} restored",
                full.len()
            );
        }
        let boundaries: Vec<(usize, S)> = (0..full.len())
            .filter_map(|cut| match Accounts::try_restore(&full[..cut]) {
                Err(RestoreError::Truncated { after }) => Some((cut, after)),
                _ => None,
            })
            .collect();
        assert_eq!(
            boundaries
                .iter()
                .map(|(_, after)| *after)
                .collect::<Vec<_>>(),
            [
                S::Header,
                S::Tenants,
                S::ApiKeys,
                S::Users,
                S::Sessions,
                S::Inventories,
                S::LinkRecords
            ],
            "one cut per section boundary, in order: {boundaries:?}"
        );
        assert_eq!(boundaries[0].0, SNAPSHOT_HEADER.len());
        assert!(
            boundaries.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "{boundaries:?}"
        );
        // The last section is followed by nothing, and by nothing more.
        let mut longer = full.clone();
        longer.push(0);
        assert_eq!(
            Accounts::try_restore(&longer).err(),
            Some(RestoreError::Malformed)
        );
    }

    #[test]
    fn an_empty_store_writes_every_section_so_its_cut_copy_is_refused_too() {
        let full = Accounts::new().snapshot();
        // The header and seven counts.
        assert_eq!(full.len(), SNAPSHOT_HEADER.len() + 7 * 4);
        assert!(Accounts::restore(&full).is_some());
        for cut in 0..full.len() {
            assert!(Accounts::restore(&full[..cut]).is_none(), "cut at {cut}");
        }
        assert_eq!(
            Accounts::try_restore(&full[..full.len() - 4]).err(),
            Some(RestoreError::Truncated {
                after: S::LinkRecords
            })
        );
    }

    /// Flip a bit, cut, insert or drop a byte, or set a count to its maximum, in
    /// a snapshot with every section filled. Restore never panics, and what it
    /// accepts is complete: written again it is as long as the bytes it came
    /// from. (Without the header, the accepted mutations that came back shorter
    /// were the cuts at section boundaries.)
    #[test]
    fn mutated_snapshots_never_panic_and_an_accepted_one_is_complete() {
        let (accounts, _) = store_with_every_section();
        let good = accounts.snapshot();
        let mut state = 0x1234_5678_9abc_def1u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0;
        for i in 0..20_000u32 {
            let mut m = good.clone();
            match i % 5 {
                0 => {
                    let at = next() as usize % m.len();
                    m[at] ^= 1 << (next() % 8);
                }
                1 => m.truncate(next() as usize % (m.len() + 1)),
                2 => {
                    let at = next() as usize % (m.len() - 4);
                    m[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                }
                3 => m.insert(next() as usize % m.len(), next() as u8),
                _ => {
                    m.remove(next() as usize % m.len());
                }
            }
            if let Ok(restored) = Accounts::try_restore(&m) {
                accepted += 1;
                assert_eq!(
                    restored.snapshot().len(),
                    m.len(),
                    "an accepted mutation must not have dropped or invented state"
                );
            }
        }
        assert!(
            accepted > 0,
            "the run must accept some mutations (bit flips in names)"
        );
    }

    // -----------------------------------------------------------------------
    // A record whose tenant or user is missing.
    // -----------------------------------------------------------------------

    /// No tenant, no API key, one user of a tenant that does not exist, no
    /// session, in the shape older servers wrote.
    fn orphan_user_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        put_u32(&mut out, 1);
        for field in ["ten_ghost", "alice", "hash"] {
            put_str(&mut out, field);
        }
        put_u32(&mut out, 0);
        out
    }

    #[test]
    fn a_snapshot_with_a_user_of_no_tenant_is_refused_with_a_typed_error() {
        let older = orphan_user_bytes();
        assert!(Accounts::restore(&older).is_none());
        assert_eq!(
            Accounts::try_restore(&older).err(),
            Some(RestoreError::Orphan { section: S::Users })
        );
        // The same records in the headed shape, with the sections that follow.
        let mut headed = SNAPSHOT_HEADER.to_vec();
        headed.extend_from_slice(&older);
        for _ in 0..3 {
            put_u32(&mut headed, 0);
        }
        assert_eq!(
            Accounts::try_restore(&headed).err(),
            Some(RestoreError::Orphan { section: S::Users })
        );
    }

    #[test]
    fn an_api_key_or_a_session_of_nothing_is_refused_too() {
        // one API key, no tenant
        let mut key = Vec::new();
        put_u32(&mut key, 0);
        put_u32(&mut key, 1);
        key.extend_from_slice(&Sha256::digest(b"tct_x"));
        for field in ["ten_ghost", "tct_x", ""] {
            put_str(&mut key, field);
        }
        put_u64(&mut key, 1);
        put_u32(&mut key, 0);
        put_u32(&mut key, 0);
        assert_eq!(
            Accounts::try_restore(&key).err(),
            Some(RestoreError::Orphan {
                section: S::ApiKeys
            })
        );
        // one tenant, one user, and a session of a user who is not there
        let mut session = Vec::new();
        put_u32(&mut session, 1);
        for field in ["ten_1", "acme", "admin@acme.example", "tenant-hash"] {
            put_str(&mut session, field);
        }
        put_u32(&mut session, 0);
        put_u32(&mut session, 1);
        for field in ["ten_1", "alice", "user-hash"] {
            put_str(&mut session, field);
        }
        put_u32(&mut session, 1);
        session.extend_from_slice(&Sha256::digest(b"t"));
        for field in ["ten_1", "nobody"] {
            put_str(&mut session, field);
        }
        put_u64(&mut session, 9);
        assert_eq!(
            Accounts::try_restore(&session).err(),
            Some(RestoreError::Orphan {
                section: S::Sessions
            })
        );
    }

    /// A user without a tenant has no directory handle. The snapshot that names
    /// one is refused, but the inventory calls must not depend on that: a panic
    /// under the store's lock would poison it, and every later call for every
    /// tenant would panic until the process restarted. A user without a tenant
    /// that reaches the store another way is refused with a typed error, and the
    /// store goes on serving.
    #[tokio::test]
    async fn a_user_without_a_tenant_cannot_panic_or_poison_the_store() {
        let mut accounts = Accounts::new();
        let (tenant, _) = accounts
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        let ghost = TenantId("ten_ghost".to_owned());
        accounts.users.insert(
            (ghost.clone(), "alice".to_owned()),
            UserRecord {
                tenant: ghost.clone(),
                username: "alice".to_owned(),
                password_hash: "not a hash".to_owned(),
            },
        );
        let store = Arc::new(AccountStore::memory(accounts));
        let device = |device_id: u32, seed: u8| DeviceBinding {
            device_id,
            identity_public_key: honest_key(seed),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        };
        let unknown_user = |result: Result<DeviceInventory, StoreError>| {
            matches!(
                result,
                Err(StoreError::Inventory(InventoryError::UnknownUser))
            )
        };

        // Each call runs in its own task, so a panic shows as a failure of this
        // test and not as an abort of the runtime.
        let s = store.clone();
        let g = ghost.clone();
        let link = tokio::spawn(async move {
            s.link_device_binding(&g, "alice", 0, [1; 32], device(1, 1))
                .await
        })
        .await
        .expect("linking for a user without a tenant must not panic");
        assert!(unknown_user(link), "link");
        let s = store.clone();
        let g = ghost.clone();
        let revoke = tokio::spawn(async move {
            s.revoke_device_binding(&g, "alice", 0, [2; 32], device(1, 1))
                .await
        })
        .await
        .expect("revoking for a user without a tenant must not panic");
        assert!(unknown_user(revoke), "revoke");
        let s = store.clone();
        let g = ghost.clone();
        let replace = tokio::spawn(async move {
            s.replace_device_binding(&g, "alice", 0, [3; 32], device(1, 1), device(2, 2))
                .await
        })
        .await
        .expect("replacing for a user without a tenant must not panic");
        assert!(unknown_user(replace), "replace");

        // The store still serves everyone else.
        store
            .sign_up_user(&tenant.id, "bob", "hunter2!!")
            .await
            .unwrap();
        let bob = store
            .link_device_binding(&tenant.id, "bob", 0, [1; 32], device(1, 1))
            .await
            .unwrap();
        assert_eq!(bob.generation, 1);
        assert_eq!(
            store.device_inventory(&tenant.id, "bob").await.unwrap(),
            Some(bob)
        );
    }
}
