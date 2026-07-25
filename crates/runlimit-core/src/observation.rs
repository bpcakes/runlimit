use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use crate::{PolicyId, ScopeId};

/// Receives synchronous, backend-neutral operational observations.
///
/// Implementations must return quickly and should hand expensive work to
/// another thread. Backends invoke observers only after releasing internal
/// locks and finalizing database transactions. A panic from an observer is
/// caught and ignored so telemetry cannot change an admission result.
///
/// Observations deliberately contain no subject keys, policy fingerprints,
/// backend error text, or other high-cardinality sensitive values.
pub trait Observer: Send + Sync + 'static {
    /// Records one operational observation.
    fn observe(&self, observation: &Observation<'_>);
}

/// A backend-neutral operational observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Observation<'a> {
    /// One admission operation completed.
    Admission(AdmissionObservation<'a>),
    /// A bounded cleanup pass completed.
    Cleanup(CleanupObservation),
    /// A bounded store reported local capacity use.
    Capacity(CapacityObservation),
}

/// Whether an admission evaluated one check or an atomic batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AdmissionOperation {
    /// One check.
    Check,
    /// An atomic batch.
    Batch,
}

/// Classification of a completed admission operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AdmissionOutcome {
    /// Quota was consumed successfully.
    Allowed,
    /// Quota exhaustion was enforced.
    QuotaDenied,
    /// Quota exhaustion was observed but not enforced.
    ShadowDenied,
    /// A hard storage bound denied admission.
    CapacityDenied,
    /// The backend or input validation failed.
    Failed,
}

/// What a caller can know about quota consumption after an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConsumptionStatus {
    /// The operation definitely consumed quota.
    Consumed,
    /// The operation definitely did not consume quota.
    NotConsumed,
    /// A failure occurred after the backend may have committed consumption.
    PossiblyConsumed,
}

/// Metadata for one completed admission operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionObservation<'a> {
    operation: AdmissionOperation,
    batch_size: usize,
    policy_id: Option<&'a PolicyId>,
    scope_id: Option<&'a ScopeId>,
    outcome: AdmissionOutcome,
    consumption: ConsumptionStatus,
    elapsed: Duration,
}

impl<'a> AdmissionObservation<'a> {
    /// Constructs admission metadata.
    pub const fn new(
        operation: AdmissionOperation,
        batch_size: usize,
        policy_id: Option<&'a PolicyId>,
        scope_id: Option<&'a ScopeId>,
        outcome: AdmissionOutcome,
        consumption: ConsumptionStatus,
        elapsed: Duration,
    ) -> Self {
        Self {
            operation,
            batch_size,
            policy_id,
            scope_id,
            outcome,
            consumption,
            elapsed,
        }
    }

    /// Returns the operation kind.
    pub const fn operation(self) -> AdmissionOperation {
        self.operation
    }

    /// Returns the number of checks submitted.
    pub const fn batch_size(self) -> usize {
        self.batch_size
    }

    /// Returns a relevant policy identifier for a single or failing check.
    pub const fn policy_id(self) -> Option<&'a PolicyId> {
        self.policy_id
    }

    /// Returns a relevant scope identifier for a single or failing check.
    pub const fn scope_id(self) -> Option<&'a ScopeId> {
        self.scope_id
    }

    /// Returns the admission outcome class.
    pub const fn outcome(self) -> AdmissionOutcome {
        self.outcome
    }

    /// Returns the quota-consumption certainty.
    pub const fn consumption(self) -> ConsumptionStatus {
        self.consumption
    }

    /// Returns wall-clock evaluation latency measured by the backend process.
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }
}

/// Metadata for one bounded cleanup pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupObservation {
    requested: usize,
    removed: Option<u64>,
    elapsed: Duration,
    consumption: ConsumptionStatus,
}

impl CleanupObservation {
    /// Constructs cleanup metadata.
    ///
    /// `removed` is `None` when a failed database operation has an unknown
    /// commit result. `consumption` describes the certainty of that effect.
    pub const fn new(
        requested: usize,
        removed: Option<u64>,
        elapsed: Duration,
        consumption: ConsumptionStatus,
    ) -> Self {
        Self {
            requested,
            removed,
            elapsed,
            consumption,
        }
    }

    /// Returns the configured maximum work for this cleanup pass.
    pub const fn requested(self) -> usize {
        self.requested
    }

    /// Returns confirmed rows or entries removed, when known.
    pub const fn removed(self) -> Option<u64> {
        self.removed
    }

    /// Returns cleanup latency.
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    /// Returns certainty about the reported cleanup effect.
    pub const fn consumption(self) -> ConsumptionStatus {
        self.consumption
    }
}

/// Local capacity use reported by a bounded backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityObservation {
    used: u64,
    capacity: u64,
    shard_index: Option<usize>,
}

impl CapacityObservation {
    /// Constructs capacity metadata.
    pub const fn new(used: u64, capacity: u64, shard_index: Option<usize>) -> Self {
        Self {
            used,
            capacity,
            shard_index,
        }
    }

    /// Returns occupied capacity units.
    pub const fn used(self) -> u64 {
        self.used
    }

    /// Returns the local hard capacity.
    pub const fn capacity(self) -> u64 {
        self.capacity
    }

    /// Returns remaining capacity.
    pub const fn headroom(self) -> u64 {
        self.capacity.saturating_sub(self.used)
    }

    /// Returns the backend-local shard index, when applicable.
    pub const fn shard_index(self) -> Option<usize> {
        self.shard_index
    }
}

/// Invokes an observer while isolating callback panics.
///
/// Backend implementations use this after releasing locks and finalizing
/// transactions. Applications normally call [`Observer::observe`] only in
/// their observer implementation.
#[doc(hidden)]
pub fn observe_safely(observer: &dyn Observer, observation: &Observation<'_>) {
    let _ = catch_unwind(AssertUnwindSafe(|| observer.observe(observation)));
}
