//! Opaque durable-operation state for the group-chat work (0091, 0132, 0134).
//!
//! This is intentionally independent of a group codec and of a concrete file
//! store: a snapshot is versioned opaque values, and a store is a narrow
//! commit and recover port. [`DurableStore`] is the handle the coordinator holds:
//! it latches after a write that did not commit and keeps generations
//! monotonic across a write whose outcome was unknown.

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
}

/// The store handle a coordinator holds (0134).
///
/// A write that is `failed` or `unknown` latches it: it then refuses every
/// commit, without forwarding it, and reports itself frozen so that the
/// coordinator declines to encrypt, decrypt or dispatch, until
/// [`recover`](OperationStore::recover) has read the durable snapshot. The
/// highest generation it has attempted or recovered is remembered so candidate
/// generations only increase.
pub struct DurableStore {
    inner: Box<dyn OperationStore + Send>,
    frozen: bool,
    high_water: u64,
}

impl DurableStore {
    /// Wrap a platform or native store.
    pub fn new(inner: impl OperationStore + Send + 'static) -> Self {
        Self {
            inner: Box::new(inner),
            frozen: false,
            high_water: 0,
        }
    }
}

impl OperationStore for DurableStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        if self.frozen {
            return CommitOutcome::Failed;
        }
        self.high_water = self.high_water.max(snapshot.generation);
        let outcome = self.inner.commit(snapshot);
        if outcome != CommitOutcome::Committed {
            self.frozen = true;
        }
        outcome
    }

    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        let recovered = self.inner.recover()?;
        if let Some(snapshot) = &recovered {
            self.high_water = self.high_water.max(snapshot.generation);
        }
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
impl OperationStore for FileOperationStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        let Some(bytes) = snapshot.encode() else {
            return CommitOutcome::Failed;
        };
        match tacenta_core::persist::write_atomically(&self.path, &bytes) {
            Ok(()) => CommitOutcome::Committed,
            Err(_) => CommitOutcome::Failed,
        }
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

        let _ = std::fs::remove_file(path);
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
}
