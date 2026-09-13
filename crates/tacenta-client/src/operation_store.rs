//! Opaque durable-operation state for the group-chat preparation work.
//!
//! This is intentionally independent of a group codec and of a concrete file
//! store. It gives crash schedules a versioned value to commit and recover
//! without claiming that current direct-message operations already use it.

/// The first combined snapshot format.
pub(crate) const OPERATION_SNAPSHOT_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationSnapshot {
    pub(crate) version: u8,
    pub(crate) generation: u64,
    pub(crate) provider_state: Vec<u8>,
    pub(crate) application_state: Vec<u8>,
    pub(crate) outbox: Vec<Vec<u8>>,
    pub(crate) inbox: Vec<Vec<u8>>,
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
            delivery_cursor: 0,
        }
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
    }
}
