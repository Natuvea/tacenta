//! Opaque durable-operation state for the group-chat work (0091, 0132, 0134).
//!
//! This is intentionally independent of a group codec and of a concrete file
//! store: a snapshot is versioned opaque values, and a store is a narrow
//! commit and recover port. [`DurableStore`] is the handle the coordinator holds:
//! it latches after a write that did not commit, keeps generations
//! monotonic across a write whose outcome was unknown, and refuses to publish
//! over a snapshot it has not seen (0143).

#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

/// The current combined snapshot format. Version two adds bounded group
/// control records while retaining read support for ungrouped version-one
/// snapshots.
pub(crate) const OPERATION_SNAPSHOT_VERSION: u8 = 2;

/// One combined durable value: opaque provider state, group state and the
/// bounded record collections of decision 0133.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSnapshot {
    pub(crate) version: u8,
    pub(crate) generation: u64,
    pub(crate) provider_state: Vec<u8>,
    pub(crate) application_state: Vec<u8>,
    pub(crate) outbox: Vec<Vec<u8>>,
    pub(crate) inbox: Vec<Vec<u8>>,
    pub(crate) dedup: Vec<Vec<u8>>,
    pub(crate) group_controls: Vec<Vec<u8>>,
    pub(crate) delivery_cursor: u64,
}

impl OperationSnapshot {
    /// The snapshot's monotonic generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The provider state a client restarts from (`connect_with_state`).
    pub fn provider_state(&self) -> &[u8] {
        &self.provider_state
    }

    pub(crate) fn empty(generation: u64) -> Self {
        Self {
            version: OPERATION_SNAPSHOT_VERSION,
            generation,
            provider_state: Vec::new(),
            application_state: Vec::new(),
            outbox: Vec::new(),
            inbox: Vec::new(),
            dedup: Vec::new(),
            group_controls: Vec::new(),
            delivery_cursor: 0,
        }
    }

    /// The snapshot's bytes, for a platform store to persist. `None` only if a
    /// value is longer than four gibibytes.
    pub fn encode(&self) -> Option<Vec<u8>> {
        fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
            out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_be_bytes());
            out.extend_from_slice(bytes);
            Some(())
        }
        fn put_many(out: &mut Vec<u8>, entries: &[Vec<u8>]) -> Option<()> {
            out.extend_from_slice(&u32::try_from(entries.len()).ok()?.to_be_bytes());
            for entry in entries {
                put_bytes(out, entry)?;
            }
            Some(())
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"TCOP");
        out.push(self.version);
        out.extend_from_slice(&self.generation.to_be_bytes());
        put_bytes(&mut out, &self.provider_state)?;
        put_bytes(&mut out, &self.application_state)?;
        put_many(&mut out, &self.outbox)?;
        put_many(&mut out, &self.inbox)?;
        put_many(&mut out, &self.dedup)?;
        put_many(&mut out, &self.group_controls)?;
        out.extend_from_slice(&self.delivery_cursor.to_be_bytes());
        Some(out)
    }

    #[cfg(test)]
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        self.encode().map(|bytes| bytes.len())
    }

    /// The inverse of [`encode`](Self::encode); `None` on any malformation,
    /// an unknown version or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        fn take<'a>(cursor: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
            let (head, tail) = cursor.split_at_checked(count)?;
            *cursor = tail;
            Some(head)
        }
        fn take_u32(cursor: &mut &[u8]) -> Option<u32> {
            Some(u32::from_be_bytes(take(cursor, 4)?.try_into().ok()?))
        }
        fn take_u64(cursor: &mut &[u8]) -> Option<u64> {
            Some(u64::from_be_bytes(take(cursor, 8)?.try_into().ok()?))
        }
        fn take_bytes(cursor: &mut &[u8]) -> Option<Vec<u8>> {
            let count = usize::try_from(take_u32(cursor)?).ok()?;
            Some(take(cursor, count)?.to_vec())
        }
        fn take_many(cursor: &mut &[u8]) -> Option<Vec<Vec<u8>>> {
            let count = usize::try_from(take_u32(cursor)?).ok()?;
            (0..count).map(|_| take_bytes(cursor)).collect()
        }

        let mut cursor = bytes;
        if take(&mut cursor, 4)? != b"TCOP" {
            return None;
        }
        let encoded_version = *take(&mut cursor, 1)?.first()?;
        if encoded_version != 1 && encoded_version != OPERATION_SNAPSHOT_VERSION {
            return None;
        }
        let generation = take_u64(&mut cursor)?;
        let provider_state = take_bytes(&mut cursor)?;
        let application_state = take_bytes(&mut cursor)?;
        let outbox = take_many(&mut cursor)?;
        let inbox = take_many(&mut cursor)?;
        let dedup = take_many(&mut cursor)?;
        let group_controls = if encoded_version == 1 {
            Vec::new()
        } else {
            take_many(&mut cursor)?
        };
        let delivery_cursor = take_u64(&mut cursor)?;
        if !cursor.is_empty() {
            return None;
        }
        Some(Self {
            // A recovered v1 value becomes v2 before its next publication;
            // otherwise encoding its added group-control field under a v1 tag
            // would make the following recovery reject trailing bytes.
            version: OPERATION_SNAPSHOT_VERSION,
            generation,
            provider_state,
            application_state,
            outbox,
            inbox,
            dedup,
            group_controls,
            delivery_cursor,
        })
    }
}

/// What a store reports for one write (0091): independent of any crypto
/// outcome. `Unknown` may or may not have reached durable storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed,
    Failed,
    Unknown,
}

/// A store could not produce its newest durable snapshot: the value was
/// unreadable, torn, of an unknown version, or the medium failed. It carries no
/// detail on purpose; recovery either yields a snapshot or refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError;

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the operation store could not be recovered")
    }
}

impl std::error::Error for StoreError {}

/// The narrow port a platform store implements for operation recovery.
pub trait OperationStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome;
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError>;

    /// Whether an earlier write left this store latched (0134): while it is,
    /// the coordinator starts no pairwise operation and publishes nothing. A
    /// plain store never latches; [`DurableStore`] does.
    fn is_frozen(&self) -> bool {
        false
    }

    /// The generation the next candidate must carry, or `None` when the
    /// counter is exhausted. A latching store keeps it above every generation
    /// it has ever been asked to publish, so an unknown write is never
    /// followed by a different snapshot under the same number (0134).
    fn next_generation(&self, current: u64) -> Option<u64> {
        current.checked_add(1)
    }

    /// The generation of the newest durable snapshot, or `None` for a store
    /// that holds none (0143). The provided implementation reads the whole
    /// snapshot; a store that can answer from a header should override it.
    fn durable_generation(&mut self) -> Result<Option<u64>, StoreError> {
        Ok(self.recover()?.map(|snapshot| snapshot.generation))
    }

    /// Publishes `snapshot` only if the newest durable snapshot still has
    /// generation `expected` (`None`: the store holds nothing). Otherwise it
    /// writes nothing and reports `failed`: another writer has published since
    /// the caller last looked, or the store cannot be read (0143).
    ///
    /// The provided implementation reads and then writes, which refuses a
    /// writer that has fallen behind but not two writers that check at the
    /// same instant. A store that can make the check and the write one atomic
    /// step (a transaction, a compare-and-swap, a lock) overrides it.
    fn commit_after(
        &mut self,
        expected: Option<u64>,
        snapshot: &OperationSnapshot,
    ) -> CommitOutcome {
        match self.durable_generation() {
            Ok(current) if current == expected => self.commit(snapshot),
            _ => CommitOutcome::Failed,
        }
    }
}

impl<T: OperationStore + ?Sized> OperationStore for Box<T> {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        (**self).commit(snapshot)
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        (**self).recover()
    }
    fn is_frozen(&self) -> bool {
        (**self).is_frozen()
    }
    fn next_generation(&self, current: u64) -> Option<u64> {
        (**self).next_generation(current)
    }
    fn durable_generation(&mut self) -> Result<Option<u64>, StoreError> {
        (**self).durable_generation()
    }
    fn commit_after(
        &mut self,
        expected: Option<u64>,
        snapshot: &OperationSnapshot,
    ) -> CommitOutcome {
        (**self).commit_after(expected, snapshot)
    }
}

/// The store handle a coordinator holds (0134, 0143).
///
/// A write that is `failed` or `unknown` latches it: it then refuses every
/// commit, without forwarding it, and reports itself frozen so that the
/// coordinator declines to encrypt, decrypt or dispatch, until
/// [`recover`](OperationStore::recover) has read the durable snapshot. The
/// highest generation it has attempted or recovered is remembered so candidate
/// generations only increase.
///
/// It also remembers the generation of the newest snapshot it recovered or
/// published, and commits with
/// [`commit_after`](OperationStore::commit_after) against it: a store that
/// holds a different generation (another writer published, a backup was put
/// back) refuses the commit, which latches like any failed write, and the
/// coordinator's `recover` reads what the store holds now. One writer per store
/// is still a precondition (0143).
pub struct DurableStore {
    inner: Box<dyn OperationStore + Send>,
    frozen: bool,
    high_water: u64,
    /// The generation of the newest snapshot this handle recovered or
    /// published; `None` while it has seen an empty store.
    observed: Option<u64>,
}

impl DurableStore {
    /// Wrap a platform or native store.
    pub fn new(inner: impl OperationStore + Send + 'static) -> Self {
        Self {
            inner: Box::new(inner),
            frozen: false,
            high_water: 0,
            observed: None,
        }
    }
}

impl OperationStore for DurableStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        if self.frozen {
            return CommitOutcome::Failed;
        }
        self.high_water = self.high_water.max(snapshot.generation);
        let outcome = self.inner.commit_after(self.observed, snapshot);
        if outcome == CommitOutcome::Committed {
            self.observed = Some(snapshot.generation);
        } else {
            self.frozen = true;
        }
        outcome
    }

    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        let recovered = self.inner.recover()?;
        if let Some(snapshot) = &recovered {
            self.high_water = self.high_water.max(snapshot.generation);
        }
        self.observed = recovered.as_ref().map(|snapshot| snapshot.generation);
        self.frozen = false;
        Ok(recovered)
    }

    fn is_frozen(&self) -> bool {
        self.frozen
    }

    fn next_generation(&self, current: u64) -> Option<u64> {
        current.max(self.high_water).checked_add(1)
    }
}

/// Native reference implementation of the operation-store port.  Platform
/// bindings provide their own store; this uses the product's crash-safe atomic
/// writer without adding a database dependency to the initial coordinator.
///
/// Every write, and the check of [`commit_after`](OperationStore::commit_after),
/// runs under an exclusive advisory lock on `<path>.lock` (0143), which stays in
/// place. The lock binds cooperating processes on one local filesystem only.
/// The store is unsealed, has no rollback detection, and reports every write
/// error as `failed`, never `unknown`.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileOperationStore {
    path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileOperationStore {
    /// A store that publishes the snapshot to `path` atomically.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FileOperationStore {
    /// The generation in the snapshot file's header (`TCOP`, version,
    /// generation), without reading or decoding the rest.
    fn header_generation(&self) -> Result<Option<u64>, StoreError> {
        use std::io::Read;
        let mut file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError),
        };
        let mut header = [0u8; 13];
        file.read_exact(&mut header).map_err(|_| StoreError)?;
        if &header[..4] != b"TCOP" || (header[4] != 1 && header[4] != OPERATION_SNAPSHOT_VERSION) {
            return Err(StoreError);
        }
        let generation: [u8; 8] = header[5..13].try_into().map_err(|_| StoreError)?;
        Ok(Some(u64::from_be_bytes(generation)))
    }

    fn write(&self, snapshot: &OperationSnapshot) -> CommitOutcome {
        let Some(bytes) = snapshot.encode() else {
            return CommitOutcome::Failed;
        };
        match tacenta_core::persist::write_atomically(&self.path, &bytes) {
            Ok(()) => CommitOutcome::Committed,
            Err(_) => CommitOutcome::Failed,
        }
    }

    /// Runs `action` while holding an exclusive advisory lock on
    /// `<path>.lock`. The atomic writer stages every write in one fixed
    /// temporary file, so two unlocked writers would also corrupt each other's
    /// staging. The lock binds cooperating processes only (0143).
    fn locked(&self, action: impl FnOnce(&Self) -> CommitOutcome) -> CommitOutcome {
        let mut lock_path = self.path.clone().into_os_string();
        lock_path.push(".lock");
        let Ok(lock) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path)
        else {
            return CommitOutcome::Failed;
        };
        if lock.lock().is_err() {
            return CommitOutcome::Failed;
        }
        let outcome = action(self);
        drop(lock);
        outcome
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl OperationStore for FileOperationStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        self.locked(|store| store.write(snapshot))
    }

    fn durable_generation(&mut self) -> Result<Option<u64>, StoreError> {
        self.header_generation()
    }

    /// The check and the write happen under one exclusive lock, so two
    /// coordinators on one local file cannot both publish from the same
    /// generation (0143).
    fn commit_after(
        &mut self,
        expected: Option<u64>,
        snapshot: &OperationSnapshot,
    ) -> CommitOutcome {
        self.locked(|store| match store.header_generation() {
            Ok(current) if current == expected => store.write(snapshot),
            _ => CommitOutcome::Failed,
        })
    }

    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => OperationSnapshot::decode(&bytes)
                .map(Some)
                .ok_or(StoreError),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StoreError),
        }
    }
}

/// Removes a native store's snapshot file and its lock file (tests).
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn remove_store_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    let mut lock = path.to_path_buf().into_os_string();
    lock.push(".lock");
    let _ = std::fs::remove_file(lock);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_snapshot_is_explicitly_versioned() {
        let snapshot = OperationSnapshot::empty(7);
        assert_eq!(snapshot.version, OPERATION_SNAPSHOT_VERSION);
        assert_eq!(snapshot.generation, 7);
        assert!(snapshot.outbox.is_empty());
        assert!(snapshot.inbox.is_empty());
        assert!(snapshot.dedup.is_empty());
        assert!(snapshot.group_controls.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_native_store_atomically_recovers_a_complete_opaque_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "tacenta-operation-store-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut snapshot = OperationSnapshot::empty(4);
        snapshot.provider_state = vec![1, 2, 3];
        snapshot.application_state = vec![4, 5];
        snapshot.outbox = vec![vec![6, 7]];
        snapshot.inbox = vec![vec![8]];
        snapshot.dedup = vec![vec![9, 10]];
        snapshot.group_controls = vec![vec![11, 12]];
        snapshot.delivery_cursor = 12;

        let mut store = FileOperationStore::new(&path);
        assert_eq!(store.commit(&snapshot), CommitOutcome::Committed);
        assert_eq!(store.recover(), Ok(Some(snapshot)));

        remove_store_files(&path);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_native_store_refuses_a_torn_or_unknown_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "tacenta-operation-store-invalid-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"TCOP\x02").unwrap();

        assert_eq!(FileOperationStore::new(&path).recover(), Err(StoreError));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_version_one_snapshot_restores_with_no_group_controls() {
        fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            out.extend_from_slice(bytes);
        }
        fn put_many(out: &mut Vec<u8>, entries: &[Vec<u8>]) {
            out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
            for entry in entries {
                put_bytes(out, entry);
            }
        }

        let mut legacy = Vec::new();
        legacy.extend_from_slice(b"TCOP");
        legacy.push(1);
        legacy.extend_from_slice(&7_u64.to_be_bytes());
        put_bytes(&mut legacy, &[1]);
        put_bytes(&mut legacy, &[2]);
        put_many(&mut legacy, &[vec![3]]);
        put_many(&mut legacy, &[vec![4]]);
        put_many(&mut legacy, &[vec![5]]);
        legacy.extend_from_slice(&6_u64.to_be_bytes());

        let migrated = OperationSnapshot {
            version: OPERATION_SNAPSHOT_VERSION,
            generation: 7,
            provider_state: vec![1],
            application_state: vec![2],
            outbox: vec![vec![3]],
            inbox: vec![vec![4]],
            dedup: vec![vec![5]],
            group_controls: Vec::new(),
            delivery_cursor: 6,
        };
        assert_eq!(OperationSnapshot::decode(&legacy), Some(migrated.clone()));
        assert_eq!(
            OperationSnapshot::decode(&migrated.encode().unwrap()),
            Some(migrated)
        );
    }

    /// Counts what reaches it and answers from a script.
    struct Counting {
        commits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        outcomes: std::collections::VecDeque<CommitOutcome>,
        durable: Option<OperationSnapshot>,
    }

    impl OperationStore for Counting {
        fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
            self.commits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let outcome = self
                .outcomes
                .pop_front()
                .unwrap_or(CommitOutcome::Committed);
            if outcome == CommitOutcome::Committed {
                self.durable = Some(snapshot.clone());
            }
            outcome
        }
        fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
            Ok(self.durable.clone())
        }
    }

    #[test]
    fn a_latched_durable_store_does_not_forward_a_commit_to_the_store_under_it() {
        let commits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut store = DurableStore::new(Counting {
            commits: commits.clone(),
            outcomes: [CommitOutcome::Unknown].into(),
            durable: None,
        });
        assert_eq!(
            store.commit(&OperationSnapshot::empty(1)),
            CommitOutcome::Unknown
        );
        assert!(store.is_frozen());
        assert_eq!(
            store.commit(&OperationSnapshot::empty(2)),
            CommitOutcome::Failed
        );
        assert_eq!(
            commits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second commit reached the store under the latch"
        );
    }

    #[test]
    fn recovery_raises_the_generation_floor_to_what_the_store_holds() {
        let mut durable = OperationSnapshot::empty(10);
        durable.provider_state = vec![1];
        let mut store = DurableStore::new(Counting {
            commits: Default::default(),
            outcomes: Default::default(),
            durable: Some(durable),
        });
        // A caller whose own copy is at 3 still gets a number above 10.
        assert_eq!(store.next_generation(3), Some(4));
        assert!(store.recover().unwrap().is_some());
        assert_eq!(store.next_generation(3), Some(11));
        assert_eq!(store.next_generation(20), Some(21));
        assert_eq!(store.next_generation(u64::MAX), None);
    }

    /// One durable value shared by two handles, as two processes on one store
    /// would share it.
    #[derive(Clone, Default)]
    struct Shared(std::sync::Arc<std::sync::Mutex<Option<OperationSnapshot>>>);

    impl OperationStore for Shared {
        fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
            *self.0.lock().unwrap() = Some(snapshot.clone());
            CommitOutcome::Committed
        }
        fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    fn marked(generation: u64, mark: u8) -> OperationSnapshot {
        let mut snapshot = OperationSnapshot::empty(generation);
        snapshot.provider_state = vec![mark];
        snapshot
    }

    #[test]
    fn a_durable_store_refuses_to_publish_over_a_snapshot_it_has_not_seen() {
        let shared = Shared::default();
        let mut first = DurableStore::new(shared.clone());
        let mut second = DurableStore::new(shared.clone());
        assert_eq!(first.recover(), Ok(None));
        assert_eq!(second.recover(), Ok(None));
        assert_eq!(first.commit(&marked(1, 1)), CommitOutcome::Committed);
        // The second handle last saw an empty store: its commit is refused, it
        // latches, and the first handle's snapshot is untouched.
        assert_eq!(second.commit(&marked(1, 2)), CommitOutcome::Failed);
        assert!(second.is_frozen());
        assert_eq!(shared.0.lock().unwrap().clone(), Some(marked(1, 1)));
        // It recovers what the store holds and then publishes above it.
        assert_eq!(second.recover(), Ok(Some(marked(1, 1))));
        assert!(!second.is_frozen());
        assert_eq!(second.commit(&marked(2, 2)), CommitOutcome::Committed);
        // Now the first handle is the one that is behind.
        assert_eq!(first.commit(&marked(2, 1)), CommitOutcome::Failed);
        assert_eq!(shared.0.lock().unwrap().clone(), Some(marked(2, 2)));
        // A handle keeps publishing while nobody else does.
        assert_eq!(second.commit(&marked(3, 2)), CommitOutcome::Committed);
        assert_eq!(second.commit(&marked(4, 2)), CommitOutcome::Committed);
    }

    #[test]
    fn a_generation_gap_after_a_write_that_did_not_land_is_not_a_second_writer() {
        // An unknown write that did not land leaves the store at the old
        // generation; the next candidate carries a higher number (0134) and must
        // still be accepted, because the store holds what the handle last saw.
        let mut store = DurableStore::new(Counting {
            commits: Default::default(),
            outcomes: [CommitOutcome::Committed, CommitOutcome::Unknown].into(),
            durable: None,
        });
        assert_eq!(store.recover(), Ok(None));
        assert_eq!(store.commit(&marked(1, 1)), CommitOutcome::Committed);
        assert_eq!(store.commit(&marked(2, 2)), CommitOutcome::Unknown);
        assert!(store.is_frozen());
        assert_eq!(store.recover(), Ok(Some(marked(1, 1))));
        assert_eq!(store.commit(&marked(3, 3)), CommitOutcome::Committed);
    }

    #[cfg(not(target_arch = "wasm32"))]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_native_store_reads_its_generation_from_the_header_and_refuses_a_stale_writer() {
        let path = scratch_path("fence");
        let mut first = FileOperationStore::new(&path);
        let mut second = FileOperationStore::new(&path);
        assert_eq!(first.durable_generation(), Ok(None));
        assert_eq!(
            first.commit_after(None, &marked(1, 1)),
            CommitOutcome::Committed
        );
        assert_eq!(second.durable_generation(), Ok(Some(1)));
        // The second handle believes the store is empty.
        assert_eq!(
            second.commit_after(None, &marked(1, 2)),
            CommitOutcome::Failed
        );
        assert_eq!(first.recover(), Ok(Some(marked(1, 1))));
        assert_eq!(
            second.commit_after(Some(1), &marked(2, 2)),
            CommitOutcome::Committed
        );
        assert_eq!(
            first.commit_after(Some(1), &marked(2, 1)),
            CommitOutcome::Failed
        );
        assert_eq!(first.recover(), Ok(Some(marked(2, 2))));
        // A header that is not a snapshot's is an error, not a generation.
        std::fs::write(&path, b"TCOP\x02").unwrap();
        assert_eq!(first.durable_generation(), Err(StoreError));
        assert_eq!(
            first.commit_after(Some(2), &marked(3, 1)),
            CommitOutcome::Failed
        );
        remove_store_files(&path);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_native_store_lets_exactly_one_of_several_racing_writers_publish_a_generation() {
        // Four handles on one file, each publishing generation g + 1 after
        // reading generation g. Without the lock two of them can both pass the
        // check; with it every success advances the generation by exactly one.
        let path = scratch_path("race");
        let successes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let threads: Vec<_> = (0..4u8)
            .map(|mark| {
                let path = path.clone();
                let successes = successes.clone();
                std::thread::spawn(move || {
                    let mut store = FileOperationStore::new(&path);
                    for _ in 0..40 {
                        let seen = store.durable_generation().unwrap();
                        let next = seen.map_or(1, |generation| generation + 1);
                        if store.commit_after(seen, &marked(next, mark)) == CommitOutcome::Committed
                        {
                            successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let wins = successes.load(std::sync::atomic::Ordering::SeqCst);
        let last = FileOperationStore::new(&path)
            .recover()
            .unwrap()
            .unwrap()
            .generation;
        assert!(wins >= 40, "each round has a winner, got {wins}");
        assert_eq!(last, wins, "two writers published from one generation");
        remove_store_files(&path);
    }
}

#[cfg(test)]
#[path = "operation_store_guard_tests.rs"]
mod guard_tests;
