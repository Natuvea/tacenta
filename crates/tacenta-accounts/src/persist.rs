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

use crate::protocol::{put_str, put_u32, put_u64, take_str, take_u32, take_u64};
use tacenta_core::crypto::groups::inventory::{
    DeviceBinding, MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS, Revocation,
};

use crate::{
    Accounts, ApiKeyRecord, DeviceInventory, TenantId, TenantRecord, UserRecord,
    inventory::{encode_inventory, validate_inventory},
};

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

impl Accounts {
    /// Serialize the whole store to bytes a caller can persist and later hand
    /// to [`restore`](Accounts::restore).
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::new();

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

        out
    }

    /// Reconstruct a store from [`snapshot`](Accounts::snapshot) bytes; `None`
    /// on any malformation. The tenant username/email indexes are rebuilt from
    /// the records.
    pub fn restore(bytes: &[u8]) -> Option<Accounts> {
        let mut accounts = Accounts::new();
        let mut rest = bytes;

        let (tenants, r) = take_u32(rest)?;
        rest = r;
        for _ in 0..tenants {
            let (id, r) = take_str(rest)?;
            let (username, r) = take_str(r)?;
            let (email, r) = take_str(r)?;
            let (password_hash, r) = take_str(r)?;
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

        let (api_keys, r) = take_u32(rest)?;
        rest = r;
        for _ in 0..api_keys {
            let (hash, r) = take_hash(rest)?;
            let (tenant, r) = take_str(r)?;
            let (prefix, r) = take_str(r)?;
            let (label, r) = take_str(r)?;
            let (created_at, r) = take_u64(r)?;
            rest = r;
            accounts.api_keys.insert(
                hash,
                ApiKeyRecord {
                    tenant: TenantId(tenant),
                    prefix,
                    label: (!label.is_empty()).then_some(label),
                    created_at,
                },
            );
        }

        let (users, r) = take_u32(rest)?;
        rest = r;
        for _ in 0..users {
            let (tenant, r) = take_str(rest)?;
            let (username, r) = take_str(r)?;
            let (password_hash, r) = take_str(r)?;
            rest = r;
            let tenant = TenantId(tenant);
            accounts.users.insert(
                (tenant.clone(), username.clone()),
                UserRecord {
                    tenant,
                    username,
                    password_hash,
                },
            );
        }

        let (sessions, r) = take_u32(rest)?;
        rest = r;
        for _ in 0..sessions {
            let (hash, r) = take_hash(rest)?;
            let (tenant, r) = take_str(r)?;
            let (username, r) = take_str(r)?;
            let (expires_at, r) = take_u64(r)?;
            rest = r;
            accounts
                .sessions
                .insert(hash, (TenantId(tenant), username, expires_at));
        }

        // Snapshots written before device inventories ended immediately after
        // sessions. Treat that exact shape as an empty inventory map so a
        // server upgrade preserves existing accounts.
        if rest.is_empty() {
            return Some(accounts);
        }
        let (inventories, r) = take_u32(rest)?;
        rest = r;
        for _ in 0..inventories {
            let (tenant, r) = take_str(rest)?;
            let (username, r) = take_str(r)?;
            let (inventory, r) = take_inventory(r)?;
            rest = r;
            let tenant = TenantId(tenant);
            let key = (tenant.clone(), username.clone());
            if !accounts.users.contains_key(&key) {
                return None;
            }
            let handle = accounts.handle(&tenant, &username)?;
            validate_inventory(&handle, &inventory).ok()?;
            if accounts.device_inventories.insert(key, inventory).is_some() {
                return None;
            }
        }

        // The preceding inventory section is present in every snapshot that
        // can contain device state. The idempotency section was appended later
        // and is optional for compatibility with those earlier snapshots.
        if rest.is_empty() {
            return Some(accounts);
        }
        let (mutations, r) = take_u32(rest)?;
        rest = r;
        for _ in 0..mutations {
            let (tenant, r) = take_str(rest)?;
            let (username, r) = take_str(r)?;
            let (idempotency_key, r) = take_hash(r)?;
            let (predecessor_generation, r) = take_u64(r)?;
            let (binding, r) = take_binding(r)?;
            let (result, r) = take_inventory(r)?;
            rest = r;
            let tenant = TenantId(tenant);
            let account_key = (tenant.clone(), username.clone());
            if !accounts.users.contains_key(&account_key) {
                return None;
            }
            let handle = accounts.handle(&tenant, &username)?;
            validate_inventory(&handle, &result).ok()?;
            if result.generation <= predecessor_generation {
                return None;
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
                return None;
            }
        }

        rest.is_empty().then_some(accounts)
    }
}

#[cfg(test)]
mod tests {
    use crate::Accounts;
    use tacenta_core::crypto::groups::inventory::{DeviceBinding, GROUP_EPOCH_V1};

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
    fn an_inventory_round_trips_and_legacy_snapshots_remain_readable() {
        let mut a = Accounts::new();
        let (tenant, _) = a
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        a.sign_up_user(&tenant.id, "alice", "hunter2!!").unwrap();
        let binding = DeviceBinding {
            device_id: 1,
            identity_public_key: [7; 32],
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

        // Before inventories, snapshots ended right after the sessions count.
        // A no-inventory new snapshot has one trailing zero count, so remove it
        // to reproduce that older exact framing.
        let mut legacy = Accounts::new();
        let (legacy_tenant, _) = legacy
            .sign_up_tenant("beta", "admin@beta.example", "correct horse")
            .unwrap();
        legacy
            .sign_up_user(&legacy_tenant.id, "bob", "hunter2!!")
            .unwrap();
        let mut bytes = legacy.snapshot();
        bytes.truncate(bytes.len() - 4);
        let restored = Accounts::restore(&bytes).expect("legacy snapshot restores");
        assert_eq!(
            restored.device_inventory(&legacy_tenant.id, "bob"),
            Some(Default::default()),
        );
    }
}
