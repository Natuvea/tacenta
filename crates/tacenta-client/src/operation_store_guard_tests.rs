//! Contract of `DurableStore` (`crates/tacenta-client/src/operation_store.rs`): a failed recovery
//! leaves the latch on, and the generation high-water mark only rises.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made.
//!
//! - M039 (`operation_store.rs:244`): `commit` overwrites the high-water mark instead of taking the
//!   maximum.
//! - M042 (`operation_store.rs:253`): `recover` lifts the latch before the recovery that can fail.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A store whose `recover` returns what its last successful `commit` wrote, as
/// a real store does: the handle checks each commit against it (0143).
struct Toggle {
    fail_commit: Arc<AtomicBool>,
    fail_recover: Arc<AtomicBool>,
    durable: Option<OperationSnapshot>,
}

impl OperationStore for Toggle {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        if self.fail_commit.load(Ordering::SeqCst) {
            CommitOutcome::Failed
        } else {
            self.durable = Some(snapshot.clone());
            CommitOutcome::Committed
        }
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        if self.fail_recover.load(Ordering::SeqCst) {
            Err(StoreError)
        } else {
            Ok(self.durable.clone())
        }
    }
}

fn toggle(commit_fails: bool, recover_fails: bool) -> (DurableStore, Arc<AtomicBool>) {
    let fail_recover = Arc::new(AtomicBool::new(recover_fails));
    let store = DurableStore::new(Toggle {
        fail_commit: Arc::new(AtomicBool::new(commit_fails)),
        fail_recover: fail_recover.clone(),
        durable: None,
    });
    (store, fail_recover)
}

/// M042 (`operation_store.rs:253`): in `DurableStore::recover`, `self.frozen = false;` moves before
/// `self.inner.recover()?`, so a recovery that fails (the store cannot be read) has already lifted
/// the latch and the coordinator resumes on state nobody recovered.
#[test]
fn m042_a_failed_recovery_leaves_the_store_latched() {
    let (mut store, fail_recover) = toggle(true, true);
    assert_eq!(
        store.commit(&OperationSnapshot::empty(1)),
        CommitOutcome::Failed
    );
    assert!(store.is_frozen());
    assert_eq!(store.recover(), Err(StoreError));
    assert!(
        store.is_frozen(),
        "a recovery that failed must not lift the latch"
    );
    fail_recover.store(false, Ordering::SeqCst);
    assert_eq!(store.recover(), Ok(None));
    assert!(!store.is_frozen());
}

/// M039 (`operation_store.rs:244`): in `DurableStore::commit`, `self.high_water =
/// self.high_water.max(snapshot.generation);` becomes `self.high_water = snapshot.generation;`: the
/// mark is overwritten by whatever generation is attempted last, so it can fall. Through the
/// coordinator this cannot be observed (candidate generations only rise), so the contract is pinned
/// on `DurableStore` itself.
#[test]
fn m039_the_high_water_mark_only_rises() {
    let (mut store, _) = toggle(false, false);
    assert_eq!(
        store.commit(&OperationSnapshot::empty(5)),
        CommitOutcome::Committed
    );
    assert_eq!(
        store.commit(&OperationSnapshot::empty(3)),
        CommitOutcome::Committed
    );
    // The next candidate is above every generation that was ever attempted.
    assert_eq!(store.next_generation(0), Some(6));
}
