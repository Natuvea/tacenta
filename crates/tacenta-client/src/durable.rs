//! Deterministic crash scheduling for the private durable-operation contract.
//!
//! This harness deliberately carries only opaque snapshot bytes.  It proves
//! the coordinator's ordering rules before a group codec or live provider is
//! connected: no handoff follows an uncommitted send snapshot, and no ACK or
//! application event follows an uncommitted inbox disposition.

use crate::operation_store::{CommitOutcome, OperationSnapshot, OperationStore};

/// Each externally relevant boundary of the first operation coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DurableBoundary {
    Preparation,
    ProviderStateMutation,
    CounterUpdate,
    SnapshotPublication,
    TransportHandoff,
    InboxCommit,
    Acknowledgement,
    EventConsumption,
}

impl DurableBoundary {
    const ALL: [Self; 8] = [
        Self::Preparation,
        Self::ProviderStateMutation,
        Self::CounterUpdate,
        Self::SnapshotPublication,
        Self::TransportHandoff,
        Self::InboxCommit,
        Self::Acknowledgement,
        Self::EventConsumption,
    ];
}

/// An injected process stop immediately before one boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CrashSchedule {
    before: DurableBoundary,
}

impl CrashSchedule {
    #[cfg(test)]
    fn before(boundary: DurableBoundary) -> Self {
        Self { before: boundary }
    }
}

/// What reached an externally visible boundary before a crash or freeze.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FaultObservation {
    pub(crate) crashed: bool,
    pub(crate) frozen: bool,
    pub(crate) send_snapshot_committed: bool,
    pub(crate) inbox_disposition_committed: bool,
    pub(crate) transport_handed_off: bool,
    pub(crate) acknowledged: bool,
    pub(crate) event_consumed: bool,
}

/// Runs one synthetic send-plus-receive trace through every durable boundary.
///
/// The trace is intentionally not the live DM path.  The live path still has
/// best-effort receive durability and cannot inherit this harness's claim.
pub(crate) struct FaultHarness<'a, S> {
    store: &'a mut S,
}

impl<'a, S: OperationStore> FaultHarness<'a, S> {
    pub(crate) fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    pub(crate) fn run(
        &mut self,
        snapshot: &OperationSnapshot,
        schedule: Option<CrashSchedule>,
    ) -> FaultObservation {
        let mut observation = FaultObservation::default();
        let mut reaches = |boundary| {
            if schedule.is_some_and(|schedule| schedule.before == boundary) {
                observation.crashed = true;
                false
            } else {
                true
            }
        };

        if !reaches(DurableBoundary::Preparation) {
            return observation;
        }
        if !reaches(DurableBoundary::ProviderStateMutation) {
            return observation;
        }
        if !reaches(DurableBoundary::CounterUpdate) {
            return observation;
        }
        if !reaches(DurableBoundary::SnapshotPublication) {
            return observation;
        }
        match self.store.commit(snapshot) {
            CommitOutcome::Committed => observation.send_snapshot_committed = true,
            CommitOutcome::Failed | CommitOutcome::Unknown => {
                observation.frozen = true;
                return observation;
            }
        }

        if !reaches(DurableBoundary::TransportHandoff) {
            return observation;
        }
        observation.transport_handed_off = true;

        if !reaches(DurableBoundary::InboxCommit) {
            return observation;
        }
        match self.store.commit(snapshot) {
            CommitOutcome::Committed => observation.inbox_disposition_committed = true,
            CommitOutcome::Failed | CommitOutcome::Unknown => {
                observation.frozen = true;
                return observation;
            }
        }

        if !reaches(DurableBoundary::Acknowledgement) {
            return observation;
        }
        observation.acknowledged = true;

        if !reaches(DurableBoundary::EventConsumption) {
            return observation;
        }
        observation.event_consumed = true;
        observation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingStore {
        outcomes: std::collections::VecDeque<CommitOutcome>,
        committed: Vec<OperationSnapshot>,
    }

    impl RecordingStore {
        fn with_outcomes(outcomes: impl IntoIterator<Item = CommitOutcome>) -> Self {
            Self {
                outcomes: outcomes.into_iter().collect(),
                committed: Vec::new(),
            }
        }
    }

    impl OperationStore for RecordingStore {
        fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
            let outcome = self
                .outcomes
                .pop_front()
                .unwrap_or(CommitOutcome::Committed);
            if outcome == CommitOutcome::Committed {
                self.committed.push(snapshot.clone());
            }
            outcome
        }

        fn recover(&mut self) -> Result<Option<OperationSnapshot>, ()> {
            Ok(self.committed.last().cloned())
        }
    }

    #[test]
    fn each_crash_boundary_blocks_outputs_that_lack_a_durable_disposition() {
        for boundary in DurableBoundary::ALL {
            let mut store = RecordingStore::default();
            let observed = FaultHarness::new(&mut store).run(
                &OperationSnapshot::empty(9),
                Some(CrashSchedule::before(boundary)),
            );

            assert!(observed.crashed, "{boundary:?} must be reachable");
            assert!(
                !observed.transport_handed_off || observed.send_snapshot_committed,
                "{boundary:?}: transport used an uncommitted send"
            );
            assert!(
                !observed.acknowledged || observed.inbox_disposition_committed,
                "{boundary:?}: ACK crossed an uncommitted inbox item"
            );
            assert!(
                !observed.event_consumed || observed.inbox_disposition_committed,
                "{boundary:?}: event used an uncommitted inbox item"
            );
        }
    }

    #[test]
    fn failed_or_unknown_publication_freezes_before_external_effects() {
        for outcome in [CommitOutcome::Failed, CommitOutcome::Unknown] {
            let mut store = RecordingStore::with_outcomes([outcome]);
            let observed = FaultHarness::new(&mut store).run(&OperationSnapshot::empty(9), None);

            assert!(observed.frozen, "{outcome:?} must freeze the operation");
            assert!(!observed.transport_handed_off);
            assert!(!observed.acknowledged);
            assert!(!observed.event_consumed);
            assert!(store.recover().unwrap().is_none());
        }
    }

    #[test]
    fn an_uncertain_inbox_commit_never_acknowledges_or_delivers_an_event() {
        let mut store =
            RecordingStore::with_outcomes([CommitOutcome::Committed, CommitOutcome::Unknown]);
        let snapshot = OperationSnapshot::empty(12);
        let observed = FaultHarness::new(&mut store).run(&snapshot, None);

        assert!(observed.send_snapshot_committed);
        assert!(observed.transport_handed_off);
        assert!(observed.frozen);
        assert!(!observed.inbox_disposition_committed);
        assert!(!observed.acknowledged);
        assert!(!observed.event_consumed);
        assert_eq!(store.recover().unwrap(), Some(snapshot));
    }
}
