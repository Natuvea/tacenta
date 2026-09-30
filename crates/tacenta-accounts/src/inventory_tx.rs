//! The order of operations of one hosted-inventory mutation on a database,
//! separated from the SQL so that the order can be tested without a database.
//!
//! [`apply_mutation`] is the whole transaction body shared by link, replace
//! and revoke; [`InventoryTx`] is the narrow set of statements it needs. The
//! Postgres store implements the trait over an open `sqlx` transaction, and the
//! tests below implement it over a small in-memory model of Postgres's
//! `READ COMMITTED` behaviour.
//!
//! # Why the order is what it is
//!
//! A mutation is a read-modify-write of one account's inventory, so two
//! mutations of the same account must not both start from the same state.
//! Two independent guards enforce that, and the tests exercise each alone.
//!
//! 1. **Lock, then read.** Every mutation first takes a lock on the account's
//!    `users` row, and only then reads the inventory, in a *separate*
//!    statement. Under `READ COMMITTED` each statement sees the rows committed
//!    when that statement began. A statement that both locks and reads (a join
//!    with `for update of users`) waits for the lock but keeps the snapshot it
//!    took before waiting, so the reader behind the lock would use the state
//!    from before the other transaction committed. The read statement that
//!    starts after the lock is held cannot see stale state, because every other
//!    mutation is waiting on that same lock.
//! 2. **Compare and set.** The write replaces the state only if the row still
//!    holds exactly the bytes that were read (or is still absent, for an
//!    account's first device). If anything wrote to the row without taking the
//!    lock, or the lock is ever weakened, the write matches nothing and the
//!    mutation is refused instead of overwriting.
//!
//! Both guards assume `READ COMMITTED`, which the Postgres store sets on the
//! transaction rather than take from the server's default. At a stricter level
//! the read after the lock would use the transaction's first snapshot; the
//! compare-and-set would then refuse a waiter that read stale state instead of
//! letting it overwrite.
//!
//! A refusal or failure at any step returns before commit, and the caller drops
//! the transaction, so nothing this function staged survives it.

use crate::TenantId;
use crate::inventory::{
    DeviceInventory, InventoryError, decode_inventory, encode_inventory, validate_inventory,
};

/// A completed mutation recorded under a client retry key.
pub(crate) struct PriorMutation {
    pub request: Vec<u8>,
    pub result: Vec<u8>,
}

/// The statements one inventory mutation issues inside an open transaction.
///
/// `username` is always the normalized form.
pub(crate) trait InventoryTx {
    /// A backend failure (for Postgres, an `sqlx::Error`).
    type Error;

    /// Take the lock that serializes every mutation of this account and return
    /// the account's directory handle (`tenant/username`), or `None` if there is
    /// no such user. Does not read the inventory.
    async fn lock_account(
        &mut self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<String>, Self::Error>;

    /// The completed mutation recorded under `key`, if any.
    async fn prior_mutation(
        &mut self,
        tenant: &TenantId,
        username: &str,
        key: &[u8; 32],
    ) -> Result<Option<PriorMutation>, Self::Error>;

    /// The stored inventory bytes (`None`: the account has no row yet). Must be
    /// a statement that begins after [`lock_account`](InventoryTx::lock_account)
    /// returned.
    async fn stored_state(
        &mut self,
        tenant: &TenantId,
        username: &str,
    ) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Replace the stored inventory with `next` only if it still equals
    /// `expected` (`None`: only if there is still no row). Returns whether it
    /// was replaced.
    async fn compare_and_set_state(
        &mut self,
        tenant: &TenantId,
        username: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Record the completed mutation under its retry key.
    async fn record_mutation(
        &mut self,
        tenant: &TenantId,
        username: &str,
        key: &[u8; 32],
        request: &[u8],
        result: &[u8],
    ) -> Result<(), Self::Error>;
}

/// Why a mutation did not complete.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MutationError<E> {
    /// A domain refusal; nothing changed.
    Refused(InventoryError),
    /// The backend failed; the caller must not commit.
    Backend(E),
}

/// Apply one mutation inside `tx`, which the caller opened and commits only on
/// `Ok`. `request` is the canonical encoding of the request (compared byte for
/// byte to detect a reused retry key), and `transition` is the pure rule that
/// turns the current inventory into the next.
pub(crate) async fn apply_mutation<T: InventoryTx>(
    tx: &mut T,
    tenant: &TenantId,
    username: &str,
    idempotency_key: [u8; 32],
    request: &[u8],
    transition: impl FnOnce(&str, &DeviceInventory) -> Result<DeviceInventory, InventoryError>,
) -> Result<DeviceInventory, MutationError<T::Error>> {
    use MutationError::{Backend, Refused};

    let handle = tx
        .lock_account(tenant, username)
        .await
        .map_err(Backend)?
        .ok_or(Refused(InventoryError::UnknownUser))?;

    if let Some(prior) = tx
        .prior_mutation(tenant, username, &idempotency_key)
        .await
        .map_err(Backend)?
    {
        if prior.request != request {
            return Err(Refused(InventoryError::IdempotencyConflict));
        }
        let result = decode_inventory(&prior.result).ok_or(Refused(InventoryError::Invalid))?;
        validate_inventory(&handle, &result).map_err(Refused)?;
        return Ok(result);
    }

    // A statement of its own, after the lock: see the module documentation.
    let stored = tx.stored_state(tenant, username).await.map_err(Backend)?;
    let current = match &stored {
        Some(bytes) => decode_inventory(bytes).ok_or(Refused(InventoryError::Invalid))?,
        None => DeviceInventory::default(),
    };
    validate_inventory(&handle, &current).map_err(Refused)?;

    let next = transition(&handle, &current).map_err(Refused)?;
    let next_bytes = encode_inventory(&next);
    let replaced = tx
        .compare_and_set_state(tenant, username, stored.as_deref(), &next_bytes)
        .await
        .map_err(Backend)?;
    if !replaced {
        // The account changed under us despite the lock. The caller's
        // predecessor generation is no longer the current one.
        return Err(Refused(InventoryError::PredecessorMismatch));
    }
    tx.record_mutation(tenant, username, &idempotency_key, request, &next_bytes)
        .await
        .map_err(Backend)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    //! A deterministic model of two transactions racing on one database.
    //!
    //! The model is `READ COMMITTED`: every statement reads what is committed
    //! at the moment it runs; a write is staged until commit; a lock or a row
    //! write blocks until its holder finishes. Each statement first yields once,
    //! standing for the network round trip, and the tests run the racers under
    //! `tokio::join!` on one thread, so the interleaving is the same on every
    //! run. What this proves is the order of operations against that model. It
    //! does not prove the SQL, and it is not a run against Postgres; the
    //! Postgres tests in `tests/pg.rs` are the check on the real database.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

    use super::*;
    use crate::inventory::{link_inventory, replace_inventory, revoke_inventory};
    use tacenta_core::crypto::groups::inventory::{
        DeviceBinding, GROUP_EPOCH_V1, binding_commitment,
    };

    type Key = (String, String);
    /// (request, result) by account and retry key.
    type Mutations = HashMap<(Key, [u8; 32]), (Vec<u8>, Vec<u8>)>;

    #[derive(Default)]
    struct Committed {
        states: HashMap<Key, Vec<u8>>,
        mutations: Mutations,
    }

    /// The shared database.
    struct Db {
        committed: Mutex<Committed>,
        /// One per account: the `users` row lock.
        account_locks: Mutex<HashMap<Key, Arc<AsyncMutex<()>>>>,
        /// One per account: the write lock of its inventory row.
        row_locks: Mutex<HashMap<Key, Arc<AsyncMutex<()>>>>,
        /// Whether `lock_account` really locks. False models a writer that
        /// does not take the lock.
        serialize: bool,
        /// How many compare-and-set writes matched nothing.
        cas_refusals: Mutex<u32>,
        /// A statement name at which the next transaction to reach it fails.
        fail_at: Mutex<Option<&'static str>>,
    }

    impl Db {
        fn new(serialize: bool) -> Arc<Db> {
            Arc::new(Db {
                committed: Mutex::new(Committed::default()),
                account_locks: Mutex::new(HashMap::new()),
                row_locks: Mutex::new(HashMap::new()),
                serialize,
                cas_refusals: Mutex::new(0),
                fail_at: Mutex::new(None),
            })
        }

        fn lock_for(
            map: &Mutex<HashMap<Key, Arc<AsyncMutex<()>>>>,
            key: &Key,
        ) -> Arc<AsyncMutex<()>> {
            map.lock().unwrap().entry(key.clone()).or_default().clone()
        }

        fn state(&self, key: &Key) -> Option<Vec<u8>> {
            self.committed.lock().unwrap().states.get(key).cloned()
        }

        fn inventory(&self, tenant: &str, user: &str) -> Option<DeviceInventory> {
            self.state(&(tenant.to_owned(), user.to_owned()))
                .map(|bytes| decode_inventory(&bytes).unwrap())
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Injected(&'static str);

    /// One open transaction.
    struct FakeTx {
        db: Arc<Db>,
        staged_states: HashMap<Key, Vec<u8>>,
        staged_mutations: Mutations,
        /// Locks held until commit or drop.
        held: Vec<OwnedMutexGuard<()>>,
    }

    impl FakeTx {
        fn begin(db: &Arc<Db>) -> FakeTx {
            FakeTx {
                db: db.clone(),
                staged_states: HashMap::new(),
                staged_mutations: HashMap::new(),
                held: Vec::new(),
            }
        }

        /// The network round trip before each statement, and fault injection.
        async fn statement(&self, name: &'static str) -> Result<(), Injected> {
            tokio::task::yield_now().await;
            if *self.db.fail_at.lock().unwrap() == Some(name) {
                return Err(Injected(name));
            }
            Ok(())
        }

        fn commit(mut self) {
            let mut committed = self.db.committed.lock().unwrap();
            committed.states.extend(self.staged_states.drain());
            committed.mutations.extend(self.staged_mutations.drain());
            // `held` drops after `committed` is released, in field order.
        }

        /// The statement this branch had before the fix: one statement that
        /// both takes the account lock and reads the inventory. The read is
        /// what was committed when the statement began; the lock wait does not
        /// refresh it (`READ COMMITTED` re-checks only the locked row).
        async fn legacy_lock_and_read(&mut self, key: &Key) -> Option<Vec<u8>> {
            tokio::task::yield_now().await;
            let snapshot = self.db.state(key);
            let lock = Db::lock_for(&self.db.account_locks, key);
            self.held.push(lock.lock_owned().await);
            snapshot
        }
    }

    impl InventoryTx for FakeTx {
        type Error = Injected;

        async fn lock_account(
            &mut self,
            tenant: &TenantId,
            username: &str,
        ) -> Result<Option<String>, Injected> {
            self.statement("lock_account").await?;
            let key = (tenant.as_str().to_owned(), username.to_owned());
            if !["alice", "bob"].contains(&username) {
                return Ok(None);
            }
            if self.db.serialize {
                let lock = Db::lock_for(&self.db.account_locks, &key);
                self.held.push(lock.lock_owned().await);
            }
            Ok(Some(format!("{}/{}", tenant.as_str(), username)))
        }

        async fn prior_mutation(
            &mut self,
            tenant: &TenantId,
            username: &str,
            key: &[u8; 32],
        ) -> Result<Option<PriorMutation>, Injected> {
            self.statement("prior_mutation").await?;
            let account = (tenant.as_str().to_owned(), username.to_owned());
            Ok(self
                .db
                .committed
                .lock()
                .unwrap()
                .mutations
                .get(&(account, *key))
                .map(|(request, result)| PriorMutation {
                    request: request.clone(),
                    result: result.clone(),
                }))
        }

        async fn stored_state(
            &mut self,
            tenant: &TenantId,
            username: &str,
        ) -> Result<Option<Vec<u8>>, Injected> {
            self.statement("stored_state").await?;
            Ok(self
                .db
                .state(&(tenant.as_str().to_owned(), username.to_owned())))
        }

        async fn compare_and_set_state(
            &mut self,
            tenant: &TenantId,
            username: &str,
            expected: Option<&[u8]>,
            next: &[u8],
        ) -> Result<bool, Injected> {
            self.statement("compare_and_set_state").await?;
            let key = (tenant.as_str().to_owned(), username.to_owned());
            // Writing the row takes its write lock, held to the end of the
            // transaction; a second writer waits and then re-checks.
            let lock = Db::lock_for(&self.db.row_locks, &key);
            self.held.push(lock.lock_owned().await);
            if self.db.state(&key).as_deref() != expected {
                *self.db.cas_refusals.lock().unwrap() += 1;
                return Ok(false);
            }
            self.staged_states.insert(key, next.to_vec());
            Ok(true)
        }

        async fn record_mutation(
            &mut self,
            tenant: &TenantId,
            username: &str,
            key: &[u8; 32],
            request: &[u8],
            result: &[u8],
        ) -> Result<(), Injected> {
            self.statement("record_mutation").await?;
            let account = (tenant.as_str().to_owned(), username.to_owned());
            self.staged_mutations
                .insert((account, *key), (request.to_vec(), result.to_vec()));
            Ok(())
        }
    }

    fn tenant() -> TenantId {
        TenantId::from_string("acme")
    }

    fn binding(device_id: u32, key: u8) -> DeviceBinding {
        DeviceBinding {
            device_id,
            identity_public_key: crate::inventory_rules_tests::honest_key(key),
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        }
    }

    fn link_request(predecessor: u64, binding: &DeviceBinding) -> Vec<u8> {
        let mut bytes = predecessor.to_be_bytes().to_vec();
        bytes.extend_from_slice(&binding.device_id.to_be_bytes());
        bytes.extend_from_slice(&binding.identity_public_key);
        bytes
    }

    /// The caller's job: open, apply, commit only on success.
    async fn link(
        db: &Arc<Db>,
        user: &str,
        predecessor: u64,
        key: u8,
        binding: DeviceBinding,
    ) -> Result<DeviceInventory, MutationError<Injected>> {
        let mut tx = FakeTx::begin(db);
        let request = link_request(predecessor, &binding);
        let next = apply_mutation(
            &mut tx,
            &tenant(),
            user,
            [key; 32],
            &request,
            move |handle, current| link_inventory(handle, current, predecessor, binding),
        )
        .await?;
        tx.commit();
        Ok(next)
    }

    async fn revoke(
        db: &Arc<Db>,
        user: &str,
        predecessor: u64,
        key: u8,
        retired: DeviceBinding,
    ) -> Result<DeviceInventory, MutationError<Injected>> {
        let mut tx = FakeTx::begin(db);
        let mut request = b"revoke".to_vec();
        request.extend_from_slice(&link_request(predecessor, &retired));
        let next = apply_mutation(
            &mut tx,
            &tenant(),
            user,
            [key; 32],
            &request,
            move |handle, current| revoke_inventory(handle, current, predecessor, retired),
        )
        .await?;
        tx.commit();
        Ok(next)
    }

    async fn replace(
        db: &Arc<Db>,
        user: &str,
        predecessor: u64,
        key: u8,
        retired: DeviceBinding,
        replacement: DeviceBinding,
    ) -> Result<DeviceInventory, MutationError<Injected>> {
        let mut tx = FakeTx::begin(db);
        let mut request = b"replace".to_vec();
        request.extend_from_slice(&link_request(predecessor, &retired));
        request.extend_from_slice(&link_request(0, &replacement));
        let next = apply_mutation(
            &mut tx,
            &tenant(),
            user,
            [key; 32],
            &request,
            move |handle, current| {
                replace_inventory(handle, current, predecessor, retired, replacement)
            },
        )
        .await?;
        tx.commit();
        Ok(next)
    }

    fn cas_refusals(db: &Db) -> u32 {
        *db.cas_refusals.lock().unwrap()
    }

    /// Two first-device links at generation 0, different retry keys, different
    /// bindings: the race PG-02's exact-predecessor rule exists to settle.
    #[tokio::test]
    async fn two_links_at_one_predecessor_admit_exactly_one() {
        let db = Db::new(true);
        let (a, b) = tokio::join!(
            link(&db, "alice", 0, 1, binding(1, 1)),
            link(&db, "alice", 0, 2, binding(2, 2)),
        );
        let (winner, loser) = match (a, b) {
            (Ok(won), Err(lost)) => (won, lost),
            (Err(lost), Ok(won)) => (won, lost),
            other => panic!("exactly one link may win generation 1, got {other:?}"),
        };
        assert_eq!(
            loser,
            MutationError::Refused(InventoryError::PredecessorMismatch)
        );
        let stored = db.inventory("acme", "alice").unwrap();
        assert_eq!(stored, winner);
        assert_eq!(stored.generation, 1);
        assert_eq!(stored.active.len(), 1);
        // The lock and the fresh read did the work; the compare-and-set was
        // never needed.
        assert_eq!(cas_refusals(&db), 0);
    }

    /// The same race with the lock taken away. The compare-and-set alone must
    /// still refuse the second writer, and refuse it as a stale predecessor.
    #[tokio::test]
    async fn the_compare_and_set_alone_stops_a_lost_update() {
        let db = Db::new(false);
        let (a, b) = tokio::join!(
            link(&db, "alice", 0, 1, binding(1, 1)),
            link(&db, "alice", 0, 2, binding(2, 2)),
        );
        let (winner, loser) = match (a, b) {
            (Ok(won), Err(lost)) => (won, lost),
            (Err(lost), Ok(won)) => (won, lost),
            other => panic!("exactly one write may land, got {other:?}"),
        };
        assert_eq!(
            loser,
            MutationError::Refused(InventoryError::PredecessorMismatch)
        );
        assert_eq!(db.inventory("acme", "alice").unwrap(), winner);
        assert_eq!(
            cas_refusals(&db),
            1,
            "the refusal came from the compare-and-set"
        );
    }

    /// The same race again, on an account that already has a row, so the
    /// compare-and-set is an update against stored bytes rather than an insert
    /// against an absent row.
    #[tokio::test]
    async fn the_compare_and_set_alone_stops_a_lost_update_on_an_existing_row() {
        let db = Db::new(false);
        link(&db, "alice", 0, 9, binding(9, 9)).await.unwrap();
        let (a, b) = tokio::join!(
            link(&db, "alice", 1, 1, binding(1, 1)),
            link(&db, "alice", 1, 2, binding(2, 2)),
        );
        assert!(a.is_ok() != b.is_ok(), "exactly one may land: {a:?} {b:?}");
        let stored = db.inventory("acme", "alice").unwrap();
        assert_eq!(stored.generation, 2);
        assert_eq!(stored.active.len(), 2, "the first device plus one new one");
        assert_eq!(cas_refusals(&db), 1);
    }

    /// Mixed lifecycle operations racing at one predecessor: a revoke and a
    /// replace of the same active binding.
    #[tokio::test]
    async fn a_revoke_and_a_replace_at_one_predecessor_admit_exactly_one() {
        let db = Db::new(true);
        let first = binding(1, 1);
        link(&db, "alice", 0, 9, first.clone()).await.unwrap();
        let successor = DeviceBinding {
            replacement_predecessor: Some(binding_commitment(&first).unwrap()),
            ..binding(2, 2)
        };
        let (a, b) = tokio::join!(
            revoke(&db, "alice", 1, 1, first.clone()),
            replace(&db, "alice", 1, 2, first.clone(), successor),
        );
        assert!(a.is_ok() != b.is_ok(), "exactly one may win: {a:?} {b:?}");
        let stored = db.inventory("acme", "alice").unwrap();
        assert_eq!(stored.generation, 2);
        assert_eq!(stored.revoked.len(), 1);
        assert_eq!(cas_refusals(&db), 0);
    }

    /// A retry racing its own original, with the same key and body, gets the
    /// original's result and applies nothing twice.
    #[tokio::test]
    async fn a_retry_racing_its_original_returns_the_committed_result() {
        let db = Db::new(true);
        let (a, b) = tokio::join!(
            link(&db, "alice", 0, 1, binding(1, 1)),
            link(&db, "alice", 0, 1, binding(1, 1)),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a, b);
        assert_eq!(a.generation, 1);
        let committed = db.committed.lock().unwrap();
        assert_eq!(committed.mutations.len(), 1, "recorded once");
        drop(committed);
        assert_eq!(db.inventory("acme", "alice").unwrap(), a);
    }

    /// A reused key with a different body races the original and is refused
    /// as a conflict, not applied as a second mutation.
    #[tokio::test]
    async fn a_reused_key_with_another_body_racing_the_original_is_a_conflict() {
        let db = Db::new(true);
        let (a, b) = tokio::join!(
            link(&db, "alice", 0, 1, binding(1, 1)),
            link(&db, "alice", 0, 1, binding(2, 2)),
        );
        let refusals: Vec<_> = [a, b].into_iter().filter_map(Result::err).collect();
        assert_eq!(
            refusals,
            vec![MutationError::Refused(InventoryError::IdempotencyConflict)]
        );
        assert_eq!(db.inventory("acme", "alice").unwrap().generation, 1);
    }

    /// The lock is per account, not global: two accounts mutate side by side.
    #[tokio::test]
    async fn different_accounts_do_not_block_each_other() {
        let db = Db::new(true);
        let (a, b) = tokio::join!(
            link(&db, "alice", 0, 1, binding(1, 1)),
            link(&db, "bob", 0, 1, binding(1, 1)),
        );
        assert_eq!(a.unwrap().generation, 1);
        assert_eq!(b.unwrap().generation, 1);
    }

    #[tokio::test]
    async fn an_unknown_user_is_refused_before_anything_is_read() {
        let db = Db::new(true);
        assert_eq!(
            link(&db, "mallory", 0, 1, binding(1, 1)).await,
            Err(MutationError::Refused(InventoryError::UnknownUser))
        );
    }

    /// A backend failure after the state write leaves neither the state nor the
    /// retry record: the caller only commits on `Ok`.
    #[tokio::test]
    async fn a_failure_after_the_state_write_commits_nothing() {
        let db = Db::new(true);
        *db.fail_at.lock().unwrap() = Some("record_mutation");
        assert_eq!(
            link(&db, "alice", 0, 1, binding(1, 1)).await,
            Err(MutationError::Backend(Injected("record_mutation")))
        );
        *db.fail_at.lock().unwrap() = None;
        assert_eq!(db.inventory("acme", "alice"), None);
        assert!(db.committed.lock().unwrap().mutations.is_empty());
        // And the account is not wedged: the same request now succeeds.
        assert_eq!(
            link(&db, "alice", 0, 1, binding(1, 1))
                .await
                .unwrap()
                .generation,
            1
        );
    }

    /// A stored state that breaks the core's bounds is refused before it is
    /// changed, whoever wrote it. The revocation floor here is above the
    /// generation, which the next generation would put right, so only the check
    /// on what was read refuses it and the check on the result cannot.
    #[tokio::test]
    async fn a_stored_state_that_breaks_the_bounds_is_refused_before_it_is_changed() {
        let db = Db::new(true);
        let broken = DeviceInventory {
            generation: 1,
            revocation_floor_generation: 2,
            ..Default::default()
        };
        let account = ("acme".to_owned(), "alice".to_owned());
        db.committed
            .lock()
            .unwrap()
            .states
            .insert(account.clone(), encode_inventory(&broken));
        assert_eq!(
            link(&db, "alice", 1, 1, binding(1, 1)).await,
            Err(MutationError::Refused(InventoryError::Invalid))
        );
        assert_eq!(
            db.state(&account),
            Some(encode_inventory(&broken)),
            "the row was not touched"
        );
    }

    /// A recorded retry result is checked before it is handed back: a record
    /// that breaks the bounds is refused, not returned as the answer.
    #[tokio::test]
    async fn a_recorded_result_that_breaks_the_bounds_is_refused_not_returned() {
        let db = Db::new(true);
        let first = binding(1, 1);
        let broken = DeviceInventory {
            generation: 1,
            revocation_floor_generation: 2,
            active: vec![first.clone()],
            ..Default::default()
        };
        let account = ("acme".to_owned(), "alice".to_owned());
        db.committed.lock().unwrap().mutations.insert(
            (account, [1; 32]),
            (link_request(0, &first), encode_inventory(&broken)),
        );
        assert_eq!(
            link(&db, "alice", 0, 1, first).await,
            Err(MutationError::Refused(InventoryError::Invalid))
        );
    }

    /// The shape this branch had before the fix, kept as an executable record
    /// of the hazard: a single statement that both locks the account and reads
    /// the inventory hands the waiter the state from before the lock wait, and
    /// an unconditional upsert then overwrites the winner. Under the model both
    /// links succeed at generation 0 and whichever committed first is lost.
    ///
    /// This drives a test-local copy of the old body, not production code; it
    /// shows why [`apply_mutation`] reads in a separate statement after the
    /// lock and writes with a compare-and-set.
    #[tokio::test]
    async fn the_previous_lock_and_read_in_one_statement_shape_loses_an_update() {
        async fn legacy_link(
            db: &Arc<Db>,
            binding: DeviceBinding,
        ) -> Result<DeviceInventory, InventoryError> {
            let account: Key = ("acme".to_owned(), "alice".to_owned());
            let mut tx = FakeTx::begin(db);
            let snapshot = tx.legacy_lock_and_read(&account).await;
            tx.statement("prior_mutation").await.unwrap();
            let current = match &snapshot {
                Some(bytes) => decode_inventory(bytes).unwrap(),
                None => DeviceInventory::default(),
            };
            let next = link_inventory("acme/alice", &current, 0, binding)?;
            // `on conflict do update set state = excluded.state`
            tx.statement("upsert").await.unwrap();
            let lock = Db::lock_for(&db.row_locks, &account);
            tx.held.push(lock.lock_owned().await);
            tx.staged_states.insert(account, encode_inventory(&next));
            tx.commit();
            Ok(next)
        }

        let db = Db::new(true);
        let (a, b) = tokio::join!(
            legacy_link(&db, binding(1, 1)),
            legacy_link(&db, binding(2, 2)),
        );
        // Both callers are told they created generation 1 with their device...
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!((a.generation, b.generation), (1, 1));
        assert_ne!(a.active, b.active);
        // ...but the store holds only one of them: the other was overwritten.
        let stored = db.inventory("acme", "alice").unwrap();
        assert_eq!(stored.generation, 1);
        assert_eq!(stored.active.len(), 1);
        assert!(stored == a || stored == b);
    }
}
