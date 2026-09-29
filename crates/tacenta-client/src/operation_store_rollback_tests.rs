//! What `DurableStore` remembers of the generations it saw committed, and what
//! `recover_not_behind` does with a store that went back (decision 0147).

use super::*;
use std::sync::{Arc, Mutex};

fn at(generation: u64) -> OperationSnapshot {
    let mut snapshot = OperationSnapshot::empty(generation);
    snapshot.provider_state = vec![generation as u8];
    snapshot
}

/// A store whose durable value tests replace from outside, and whose next commits can be scripted.
#[derive(Clone, Default)]
struct Outside {
    durable: Arc<Mutex<Option<OperationSnapshot>>>,
    script: Arc<Mutex<Vec<(CommitOutcome, bool)>>>,
}

impl Outside {
    fn put(&self, snapshot: Option<OperationSnapshot>) {
        *self.durable.lock().unwrap() = snapshot;
    }

    fn generation(&self) -> Option<u64> {
        self.durable
            .lock()
            .unwrap()
            .as_ref()
            .map(OperationSnapshot::generation)
    }
}

impl OperationStore for Outside {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        let (outcome, lands) = {
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                (CommitOutcome::Committed, true)
            } else {
                script.remove(0)
            }
        };
        if lands {
            *self.durable.lock().unwrap() = Some(snapshot.clone());
        }
        outcome
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        Ok(self.durable.lock().unwrap().clone())
    }
}

/// A handle that published generations 1 to 3.
fn handle_at_three() -> (DurableStore, Outside) {
    let outside = Outside::default();
    let mut handle = DurableStore::new(outside.clone());
    for generation in 1..=3 {
        assert_eq!(handle.commit(&at(generation)), CommitOutcome::Committed);
    }
    (handle, outside)
}

/// A store that went back below what the handle committed is refused, however often it is asked,
/// and the handle stays latched; the same store at the committed generation, or ahead, is read.
#[test]
fn a_store_behind_the_highest_committed_generation_is_refused_and_stays_latched() {
    let (mut handle, outside) = handle_at_three();
    outside.put(Some(at(2)));
    for _ in 0..2 {
        assert_eq!(handle.recover_not_behind(), Err(RecoverError::RolledBack));
        assert!(handle.is_frozen());
    }
    // The refusal remembered nothing: the store is still not where the handle expects, and a
    // commit is refused.
    assert_eq!(handle.commit(&at(4)), CommitOutcome::Failed);
    assert_eq!(outside.generation(), Some(2));
    // The store comes back to the committed generation, and then goes ahead.
    outside.put(Some(at(3)));
    assert_eq!(handle.recover_not_behind().unwrap().unwrap().generation, 3);
    assert!(!handle.is_frozen());
    outside.put(Some(at(9)));
    assert_eq!(handle.recover_not_behind().unwrap().unwrap().generation, 9);
    // Having recovered generation 9, a return to 3 is now a rollback.
    outside.put(Some(at(3)));
    assert_eq!(handle.recover_not_behind(), Err(RecoverError::RolledBack));
}

/// A store found empty after the handle committed holds nothing to adopt. It is not reported as a
/// rollback: the coordinator's `recover` answers `Recovery` for it, as 0143 says.
#[test]
fn a_store_found_empty_after_a_commit_yields_nothing() {
    let (mut handle, outside) = handle_at_three();
    outside.put(None);
    assert_eq!(handle.recover_not_behind(), Ok(None));
}

/// A write that failed, or whose outcome was unknown, does not raise the mark: whether an unknown
/// write landed is what recovery finds out, and both answers are legitimate.
#[test]
fn a_write_that_failed_or_was_in_doubt_does_not_raise_the_mark() {
    for (outcome, lands) in [
        (CommitOutcome::Failed, false),
        (CommitOutcome::Unknown, false),
        (CommitOutcome::Unknown, true),
    ] {
        let (mut handle, outside) = handle_at_three();
        outside.script.lock().unwrap().push((outcome, lands));
        assert_eq!(handle.commit(&at(4)), outcome);
        assert!(handle.is_frozen());
        let expected = if lands { 4 } else { 3 };
        assert_eq!(
            handle.recover_not_behind().unwrap().unwrap().generation,
            expected,
            "{outcome:?} lands {lands}"
        );
        assert!(!handle.is_frozen());
        // The mark is what was recovered, so a store that then goes back is refused.
        outside.put(Some(at(2)));
        assert_eq!(handle.recover_not_behind(), Err(RecoverError::RolledBack));
    }
}

/// A handle that has seen nothing accepts any snapshot: the mark lives in the handle (0147), so a
/// new coordinator over the same store has no memory of the newer snapshot.
#[test]
fn a_new_handle_has_no_mark() {
    let (_, outside) = handle_at_three();
    outside.put(Some(at(2)));
    let mut fresh = DurableStore::new(outside.clone());
    assert_eq!(fresh.recover_not_behind().unwrap().unwrap().generation, 2);
    let mut empty = DurableStore::new(Outside::default());
    assert_eq!(empty.recover_not_behind(), Ok(None));
}

/// The port's own `recover` is unchanged: it adopts whatever the store holds and lifts the latch.
/// The refusal is `recover_not_behind`'s, which the coordinator's `recover` uses.
#[test]
fn the_plain_recover_still_adopts_what_the_store_holds() {
    let (mut handle, outside) = handle_at_three();
    outside.put(Some(at(2)));
    assert_eq!(handle.commit(&at(4)), CommitOutcome::Failed);
    assert!(handle.is_frozen());
    assert_eq!(handle.recover().unwrap().unwrap().generation, 2);
    assert!(!handle.is_frozen());
}
