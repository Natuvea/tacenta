//! Guards of the store port and its native file store after decision 0143
//! (`crates/tacenta-client/src/operation_store.rs`): what a boxed store forwards, what the file
//! store reads from a snapshot's header, and that its writes and its compare-and-write are done
//! under the exclusive lock.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made.
//!
//! - R014, R015, R016: `impl OperationStore for Box<T>` does not forward `durable_generation`,
//!   `next_generation` or `is_frozen`.
//! - R019, R020: `FileOperationStore::header_generation` refuses a version-one file or does not
//!   check the `TCOP` magic.
//! - R022, R024: the exclusive lock is never taken, or `commit` does not take it.
//! - R023: a lock file that cannot be opened is reported as a committed write.
//! - R028: `FileOperationStore::recover` treats a missing file as an error.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A store that answers every defaulted method of the port with a value the default would not give.
struct Marked {
    log: Arc<Mutex<Vec<&'static str>>>,
}

impl OperationStore for Marked {
    fn commit(&mut self, _snapshot: &OperationSnapshot) -> CommitOutcome {
        self.log.lock().unwrap().push("commit");
        CommitOutcome::Committed
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        Ok(None)
    }
    fn is_frozen(&self) -> bool {
        true
    }
    fn next_generation(&self, current: u64) -> Option<u64> {
        Some(current + 100)
    }
    fn durable_generation(&mut self) -> Result<Option<u64>, StoreError> {
        Ok(Some(41))
    }
    fn commit_after(
        &mut self,
        _expected: Option<u64>,
        _snapshot: &OperationSnapshot,
    ) -> CommitOutcome {
        self.log.lock().unwrap().push("commit_after");
        CommitOutcome::Failed
    }
}

fn boxed() -> Box<dyn OperationStore> {
    Box::new(Marked {
        log: Arc::new(Mutex::new(Vec::new())),
    })
}

/// R014: `impl OperationStore for Box<T>` answers `durable_generation` with an empty store instead of
/// asking the wrapped store.
#[test]
fn r014_a_boxed_store_reports_the_wrapped_stores_durable_generation() {
    let mut store = boxed();
    assert_eq!(
        <Box<dyn OperationStore> as OperationStore>::durable_generation(&mut store),
        Ok(Some(41))
    );
}

/// R015: `impl OperationStore for Box<T>` computes the next generation itself instead of asking the
/// wrapped store.
#[test]
fn r015_a_boxed_store_asks_the_wrapped_store_for_the_next_generation() {
    let store = boxed();
    assert_eq!(
        <Box<dyn OperationStore> as OperationStore>::next_generation(&store, 5),
        Some(105)
    );
}

/// R016: `impl OperationStore for Box<T>` reports itself not frozen whatever the wrapped store says.
#[test]
fn r016_a_boxed_store_reports_the_wrapped_stores_latch() {
    let store = boxed();
    assert!(<Box<dyn OperationStore> as OperationStore>::is_frozen(
        &store
    ));
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "tacenta-operation-store-{name}-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn header(version: u8, generation: u64) -> Vec<u8> {
    let mut bytes = b"TCOP".to_vec();
    bytes.push(version);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes
}

/// R019: `FileOperationStore::header_generation` refuses a version-one file, which `decode` still
/// reads, so a store holding one reports no durable generation and `commit_after` is refused.
#[test]
fn r019_the_header_generation_is_read_from_a_version_one_and_a_version_two_file() {
    let path = temp_path("header-versions");
    let mut store = FileOperationStore::new(&path);
    std::fs::write(&path, header(1, 9)).unwrap();
    assert_eq!(store.durable_generation(), Ok(Some(9)));
    std::fs::write(&path, header(OPERATION_SNAPSHOT_VERSION, 12)).unwrap();
    assert_eq!(store.durable_generation(), Ok(Some(12)));
    std::fs::write(&path, header(OPERATION_SNAPSHOT_VERSION + 1, 12)).unwrap();
    assert_eq!(store.durable_generation(), Err(StoreError));
    remove_store_files(&path);
}

/// R020: `FileOperationStore::header_generation` does not check the `TCOP` magic, so any file of 13
/// bytes or more has a durable generation.
#[test]
fn r020_a_file_without_the_snapshot_magic_has_no_durable_generation() {
    let path = temp_path("header-magic");
    let mut store = FileOperationStore::new(&path);
    let mut not_ours = header(OPERATION_SNAPSHOT_VERSION, 7);
    not_ours[..4].copy_from_slice(b"XXXX");
    std::fs::write(&path, not_ours).unwrap();
    assert_eq!(store.durable_generation(), Err(StoreError));
    remove_store_files(&path);
}

/// Holds the store's lock file exclusively, runs `write` on another thread, and reports whether the
/// write finished while the lock was held and what it returned after the lock was released.
fn write_while_the_lock_is_held(
    name: &str,
    write: impl FnOnce(&mut FileOperationStore) -> CommitOutcome + Send + 'static,
) -> (bool, CommitOutcome) {
    let path = temp_path(name);
    let mut lock_path = path.clone().into_os_string();
    lock_path.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .unwrap();
    lock.lock().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || {
        let mut store = FileOperationStore::new(&writer_path);
        sender.send(write(&mut store)).unwrap();
    });
    let finished_early = receiver.recv_timeout(Duration::from_millis(500)).is_ok();
    drop(lock);
    let outcome = if finished_early {
        CommitOutcome::Failed
    } else {
        receiver.recv_timeout(Duration::from_secs(30)).unwrap()
    };
    writer.join().unwrap();
    remove_store_files(&path);
    (finished_early, outcome)
}

/// R022: `FileOperationStore::locked` never takes the exclusive lock, so a compare-and-write runs
/// while another holder has the lock.
#[test]
fn r022_a_compare_and_write_waits_for_the_exclusive_lock() {
    let (finished_early, outcome) = write_while_the_lock_is_held("locked-commit-after", |store| {
        store.commit_after(None, &OperationSnapshot::empty(1))
    });
    assert!(!finished_early, "the write must wait for the lock");
    assert_eq!(outcome, CommitOutcome::Committed);
}

/// R024: `FileOperationStore::commit` writes without taking the lock, so a plain write runs while
/// another holder has the lock.
#[test]
fn r024_a_plain_write_waits_for_the_exclusive_lock() {
    let (finished_early, outcome) = write_while_the_lock_is_held("locked-commit", |store| {
        store.commit(&OperationSnapshot::empty(1))
    });
    assert!(!finished_early, "the write must wait for the lock");
    assert_eq!(outcome, CommitOutcome::Committed);
}

/// R023: `FileOperationStore::locked` reports a write committed when its lock file cannot be
/// opened.
#[test]
fn r023_a_write_whose_lock_file_cannot_be_opened_is_failed() {
    let missing = temp_path("no-such-directory");
    let path = missing.join("store.bin");
    let mut store = FileOperationStore::new(&path);
    assert_eq!(
        store.commit(&OperationSnapshot::empty(1)),
        CommitOutcome::Failed
    );
    assert_eq!(
        store.commit_after(None, &OperationSnapshot::empty(1)),
        CommitOutcome::Failed
    );
}

/// R028: `FileOperationStore::recover` reports a missing file as an error instead of an empty store.
#[test]
fn r028_a_missing_file_recovers_as_an_empty_store() {
    let path = temp_path("missing");
    assert_eq!(FileOperationStore::new(&path).recover(), Ok(None));
}
