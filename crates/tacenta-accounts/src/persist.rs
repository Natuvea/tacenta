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
use crate::{Accounts, ApiKeyRecord, TenantId, TenantRecord, UserRecord};

fn put_hash(out: &mut Vec<u8>, hash: &[u8; 32]) {
    out.extend_from_slice(hash);
}

fn take_hash(bytes: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (head, rest) = bytes.split_at_checked(32)?;
    Some((head.try_into().ok()?, rest))
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

        rest.is_empty().then_some(accounts)
    }
}

#[cfg(test)]
mod tests {
    use crate::Accounts;

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
}
