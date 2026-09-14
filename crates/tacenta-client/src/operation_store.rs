//! Opaque durable-operation state for the group-chat preparation work.
//!
//! This is intentionally independent of a group codec and of a concrete file
//! store. It gives crash schedules a versioned value to commit and recover
//! without claiming that current direct-message operations already use it.

#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

/// The current combined snapshot format. Version two adds bounded group
/// control records while retaining read support for ungrouped version-one
/// snapshots.
pub(crate) const OPERATION_SNAPSHOT_VERSION: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationSnapshot {
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

    #[cfg(not(target_arch = "wasm32"))]
    fn encode(&self) -> Option<Vec<u8>> {
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

    #[cfg(not(target_arch = "wasm32"))]
    fn decode(bytes: &[u8]) -> Option<Self> {
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
        let version = *take(&mut cursor, 1)?.first()?;
        if version != 1 && version != OPERATION_SNAPSHOT_VERSION {
            return None;
        }
        let generation = take_u64(&mut cursor)?;
        let provider_state = take_bytes(&mut cursor)?;
        let application_state = take_bytes(&mut cursor)?;
        let outbox = take_many(&mut cursor)?;
        let inbox = take_many(&mut cursor)?;
        let dedup = take_many(&mut cursor)?;
        let group_controls = if version == 1 {
            Vec::new()
        } else {
            take_many(&mut cursor)?
        };
        let delivery_cursor = take_u64(&mut cursor)?;
        if !cursor.is_empty() {
            return None;
        }
        Some(Self {
            version,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitOutcome {
    Committed,
    Failed,
    Unknown,
}

/// The narrow port a platform store implements for operation recovery.
pub(crate) trait OperationStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome;
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, ()>;
}

/// Native reference implementation of the operation-store port.  Platform
/// bindings provide their own store; this uses the product's crash-safe atomic
/// writer without adding a database dependency to the initial coordinator.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct FileOperationStore {
    path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileOperationStore {
    pub(crate) fn new(path: impl AsRef<Path>) -> Self {
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

    fn recover(&mut self) -> Result<Option<OperationSnapshot>, ()> {
        match std::fs::read(&self.path) {
            Ok(bytes) => OperationSnapshot::decode(&bytes).map(Some).ok_or(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(()),
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

        assert_eq!(FileOperationStore::new(&path).recover(), Err(()));
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

        assert_eq!(
            OperationSnapshot::decode(&legacy),
            Some(OperationSnapshot {
                version: 1,
                generation: 7,
                provider_state: vec![1],
                application_state: vec![2],
                outbox: vec![vec![3]],
                inbox: vec![vec![4]],
                dedup: vec![vec![5]],
                group_controls: Vec::new(),
                delivery_cursor: 6,
            })
        );
    }
}
