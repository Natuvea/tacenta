//! Guards for the write fence of decision 0143 (`operation_store.rs`): what the fence does when the
//! store went back or cannot be read, what a handle believes after it recovered an empty store, and
//! that the native store's lock is exclusive, is taken before the header is read and is held while
//! the snapshot is written. They came from a mutation run of the second fix round.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc
//! comment is made.
//!
//! - `DurableStore::commit` remembers the high-water mark instead of the generation written.
//! - `DurableStore::recover` keeps the generation it observed before when the store now holds
//!   nothing.
//! - The compare in the provided `commit_after` or in the file store's accepts a store that is
//!   behind the expected generation (`<=` for `==`).
//! - The provided `commit_after` writes to a store that cannot be read, or the provided
//!   `durable_generation` reports such a store as empty.
//! - `FileOperationStore::header_generation` reports a file that cannot be opened (for a reason
//!   other than that it is missing) as an empty store.
//! - The file store releases its lock before the compare and the write, takes a shared lock
//!   instead of an exclusive one, or reads the header before it holds the lock.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A snapshot that can be told from another by its generation and mark.
fn marked(generation: u64, mark: u8) -> OperationSnapshot {
    let mut snapshot = OperationSnapshot::empty(generation);
    snapshot.provider_state = vec![mark];
    snapshot
}

/// A store with no `commit_after` of its own (the provided one is under test), whose durable value
/// can be replaced from outside, as another writer or a restored backup would, and whose reads can
/// be made to fail.
#[derive(Clone, Default)]
struct Outside {
    durable: Arc<Mutex<Option<OperationSnapshot>>>,
    unreadable: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
}

impl OperationStore for Outside {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.durable.lock().unwrap() = Some(snapshot.clone());
        CommitOutcome::Committed
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        if self.unreadable.load(Ordering::SeqCst) {
            Err(StoreError)
        } else {
            Ok(self.durable.lock().unwrap().clone())
        }
    }
}

/// In `DurableStore::recover`, `self.observed` keeps its previous value when the store now
/// holds nothing (`.or(self.observed)`), so a handle that published generation 3 and then finds the
/// store empty still expects generation 3 and refuses a commit onto the empty store.
#[test]
fn a_store_found_empty_is_expected_empty_by_the_next_commit() {
    let outside = Outside::default();
    let mut handle = DurableStore::new(outside.clone());
    assert_eq!(handle.commit(&marked(3, 1)), CommitOutcome::Committed);
    *outside.durable.lock().unwrap() = None;
    assert_eq!(handle.recover(), Ok(None));
    assert_eq!(handle.commit(&marked(4, 1)), CommitOutcome::Committed);
    assert!(!handle.is_frozen());
}

/// In `DurableStore::commit`, the generation remembered after a committed write is the
/// high-water mark instead of the generation written. The two differ only when a caller publishes
/// below a generation it attempted before (the coordinator never does: its candidates are above
/// the mark), so this pins the contract of the handle itself: it expects the store to hold what it
/// wrote last.
#[test]
fn the_handle_expects_the_generation_it_wrote_last() {
    let outside = Outside::default();
    let mut handle = DurableStore::new(outside.clone());
    assert_eq!(handle.commit(&marked(5, 1)), CommitOutcome::Committed);
    assert_eq!(handle.commit(&marked(3, 1)), CommitOutcome::Committed);
    assert_eq!(handle.commit(&marked(4, 1)), CommitOutcome::Committed);
    assert_eq!(outside.durable.lock().unwrap().clone(), Some(marked(4, 1)));
}

/// In the provided `commit_after`, `current == expected` becomes `current <= expected`, so a
/// store that has gone back below the generation the handle published (a backup put back) is
/// published to instead of refused.
#[test]
fn a_store_that_went_back_below_the_observed_generation_refuses_the_commit() {
    let outside = Outside::default();
    let mut handle = DurableStore::new(outside.clone());
    assert_eq!(handle.commit(&marked(5, 1)), CommitOutcome::Committed);
    *outside.durable.lock().unwrap() = Some(marked(2, 9));
    assert_eq!(handle.commit(&marked(6, 1)), CommitOutcome::Failed);
    assert!(handle.is_frozen());
    assert_eq!(outside.durable.lock().unwrap().clone(), Some(marked(2, 9)));
    assert_eq!(outside.writes.load(Ordering::SeqCst), 1);
}

/// In the provided `commit_after` an `Err` from the read publishes anyway, or
/// the provided `durable_generation` turns the read error into "no snapshot", so a handle
/// that last saw an empty store writes over a store it cannot read.
#[test]
fn a_store_that_cannot_be_read_is_never_written_to() {
    // A handle that last saw an empty store, over a store that cannot be read.
    let outside = Outside::default();
    outside.unreadable.store(true, Ordering::SeqCst);
    let mut handle = DurableStore::new(outside.clone());
    assert_eq!(handle.commit(&marked(1, 1)), CommitOutcome::Failed);
    assert!(handle.is_frozen());
    assert_eq!(outside.writes.load(Ordering::SeqCst), 0);
    // A handle that has published, over a store that then becomes unreadable.
    let outside = Outside::default();
    let mut handle = DurableStore::new(outside.clone());
    assert_eq!(handle.commit(&marked(1, 1)), CommitOutcome::Committed);
    outside.unreadable.store(true, Ordering::SeqCst);
    assert_eq!(handle.commit(&marked(2, 1)), CommitOutcome::Failed);
    assert_eq!(outside.writes.load(Ordering::SeqCst), 1);
}

fn scratch_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tacenta-operation-store-{name}-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn lock_path_of(path: &Path) -> PathBuf {
    let mut lock = path.to_path_buf().into_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn open_lock_file(path: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path_of(path))
        .unwrap()
}

/// In `FileOperationStore::commit_after`, `current == expected` becomes `current <= expected`,
/// so a file that has gone back below the generation the handle expects is written over.
#[test]
fn a_file_that_went_back_below_the_expected_generation_refuses_the_write() {
    let path = scratch_path("killer-rollback");
    let mut store = FileOperationStore::new(&path);
    assert_eq!(
        store.commit_after(None, &marked(1, 1)),
        CommitOutcome::Committed
    );
    // The handle believes generation 2 was published; the file holds generation 1.
    assert_eq!(
        store.commit_after(Some(2), &marked(3, 2)),
        CommitOutcome::Failed
    );
    assert_eq!(store.recover(), Ok(Some(marked(1, 1))));
    remove_store_files(&path);
}

/// In `FileOperationStore::header_generation`, an open error other than "not found" becomes
/// `Ok(None)`, so a path that cannot be opened has an empty store's generation and a handle that
/// last saw an empty store may write over it. A path below a regular file is such a path.
#[cfg(unix)]
#[test]
fn a_store_path_that_cannot_be_opened_has_no_readable_generation() {
    let file = scratch_path("killer-not-a-directory");
    std::fs::write(&file, b"a file, not a directory").unwrap();
    let mut store = FileOperationStore::new(file.join("store.bin"));
    assert_eq!(store.durable_generation(), Err(StoreError));
    let _ = std::fs::remove_file(file);
}

/// In `FileOperationStore::locked`, `lock()` becomes `lock_shared()`, so a writer proceeds
/// while another holder has the lock shared (two writers would hold it at once).
#[test]
fn a_write_waits_for_a_shared_holder_of_the_lock_too() {
    let path = scratch_path("killer-shared-holder");
    let holder = open_lock_file(&path);
    holder.lock_shared().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || {
        let mut store = FileOperationStore::new(&writer_path);
        sender
            .send(store.commit_after(None, &marked(1, 1)))
            .unwrap();
    });
    let finished_early = receiver.recv_timeout(Duration::from_millis(500)).is_ok();
    drop(holder);
    assert!(!finished_early, "the write must wait for a shared holder");
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(30)).unwrap(),
        CommitOutcome::Committed
    );
    writer.join().unwrap();
    remove_store_files(&path);
}

/// In `FileOperationStore::commit_after` the header is read before the lock is taken, so a
/// writer that waits for the lock compares against a generation another writer has since replaced.
#[test]
fn the_header_is_read_under_the_lock() {
    let path = scratch_path("killer-header-under-lock");
    let holder = open_lock_file(&path);
    holder.lock().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || {
        let mut store = FileOperationStore::new(&writer_path);
        sender
            .send(store.commit_after(None, &marked(1, 2)))
            .unwrap();
    });
    // The writer is waiting for the lock.
    assert!(
        receiver.recv_timeout(Duration::from_millis(500)).is_err(),
        "the write must wait for the lock"
    );
    // Meanwhile the holder publishes generation 1 (it holds the lock).
    std::fs::write(&path, marked(1, 9).encode().unwrap()).unwrap();
    drop(holder);
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(30)).unwrap(),
        CommitOutcome::Failed,
        "the writer expected an empty store and must see the holder's snapshot"
    );
    writer.join().unwrap();
    assert_eq!(
        FileOperationStore::new(&path).recover(),
        Ok(Some(marked(1, 9)))
    );
    remove_store_files(&path);
}

/// In `FileOperationStore::locked` the lock is released before the action runs, so the
/// compare and the write happen outside it. While a stream of large writes goes on, another
/// handle of the lock file that keeps trying the lock must find it held for most of the time.
#[test]
fn the_lock_is_held_while_the_snapshot_is_written() {
    let path = scratch_path("killer-lock-held");
    let stop = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let held = Arc::new(AtomicUsize::new(0));
    let poller = {
        let (stop, polls, held) = (stop.clone(), polls.clone(), held.clone());
        let probe = open_lock_file(&path);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match probe.try_lock() {
                    Ok(()) => {
                        polls.fetch_add(1, Ordering::SeqCst);
                        probe.unlock().unwrap();
                    }
                    Err(std::fs::TryLockError::WouldBlock) => {
                        polls.fetch_add(1, Ordering::SeqCst);
                        held.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(std::fs::TryLockError::Error(error)) => panic!("{error}"),
                }
            }
        })
    };
    let mut store = FileOperationStore::new(&path);
    let mut big = marked(1, 1);
    big.provider_state = vec![7u8; 8 << 20];
    let mut previous = None;
    for generation in 1..=12u64 {
        big.generation = generation;
        assert_eq!(store.commit_after(previous, &big), CommitOutcome::Committed);
        previous = Some(generation);
    }
    stop.store(true, Ordering::SeqCst);
    poller.join().unwrap();
    let (polls, held) = (polls.load(Ordering::SeqCst), held.load(Ordering::SeqCst));
    assert!(polls >= 100, "the probe ran only {polls} times");
    assert!(
        held * 4 >= polls,
        "the lock was found held {held} times in {polls}: it is not held while the snapshot is written"
    );
    remove_store_files(&path);
}
