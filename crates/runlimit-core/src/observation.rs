use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use crate::{
    BatchDecision, BatchDecisionView, Check, Decision, DecisionView, Denial, DenialKind, PolicyId,
    RateLimitPolicy, ScopeId,
};

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

    /// Builds admission metadata from one completed check decision.
    ///
    /// Only an allowed decision is recorded as having consumed quota. Quota,
    /// shadow-quota, and storage-capacity denials receive their corresponding
    /// backend-neutral outcome classifications.
    pub fn from_check<P: RateLimitPolicy + ?Sized>(
        check: &Check<'a, P>,
        decision: &Decision,
        elapsed: Duration,
    ) -> Self {
        let (outcome, consumption) = classify_decision(decision);
        Self::from_relevant_check(
            AdmissionOperation::Check,
            1,
            Some(check),
            outcome,
            consumption,
            elapsed,
        )
    }

    /// Builds admission metadata from one completed atomic batch decision.
    ///
    /// A successful nonempty batch is recorded as consuming quota. An allowed
    /// batch receives policy metadata only when its decision contains exactly
    /// one allowed check; a denied batch receives the metadata of its reported
    /// failing input when that input is present.
    pub fn from_batch<P: RateLimitPolicy + ?Sized>(
        checks: &[Check<'a, P>],
        decision: &BatchDecision,
        elapsed: Duration,
    ) -> Self {
        let (outcome, consumption) = classify_batch(decision, checks.is_empty());
        Self::from_relevant_check(
            AdmissionOperation::Batch,
            checks.len(),
            batch_relevant_check(checks, decision),
            outcome,
            consumption,
            elapsed,
        )
    }

    fn from_relevant_check<P: RateLimitPolicy + ?Sized>(
        operation: AdmissionOperation,
        batch_size: usize,
        relevant_check: Option<&Check<'a, P>>,
        outcome: AdmissionOutcome,
        consumption: ConsumptionStatus,
        elapsed: Duration,
    ) -> Self {
        let (policy_id, scope_id) = relevant_check.map_or((None, None), |check| {
            (Some(check.policy().id()), Some(check.policy().scope()))
        });
        Self::new(
            operation,
            batch_size,
            policy_id,
            scope_id,
            outcome,
            consumption,
            elapsed,
        )
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

fn classify_decision(decision: &Decision) -> (AdmissionOutcome, ConsumptionStatus) {
    match decision.view() {
        DecisionView::Allowed { .. } => (AdmissionOutcome::Allowed, ConsumptionStatus::Consumed),
        DecisionView::Denied { denial } => classify_denial(denial),
        DecisionView::ShadowDenied { .. } => (
            AdmissionOutcome::ShadowDenied,
            ConsumptionStatus::NotConsumed,
        ),
    }
}

fn classify_batch(decision: &BatchDecision, empty: bool) -> (AdmissionOutcome, ConsumptionStatus) {
    match decision.view() {
        BatchDecisionView::Allowed { .. } => (
            AdmissionOutcome::Allowed,
            if empty {
                ConsumptionStatus::NotConsumed
            } else {
                ConsumptionStatus::Consumed
            },
        ),
        BatchDecisionView::Denied { denial, .. } => classify_denial(denial),
        BatchDecisionView::ShadowDenied { .. } => (
            AdmissionOutcome::ShadowDenied,
            ConsumptionStatus::NotConsumed,
        ),
    }
}

const fn classify_denial(denial: &Denial) -> (AdmissionOutcome, ConsumptionStatus) {
    match denial.kind() {
        DenialKind::QuotaExceeded => (
            AdmissionOutcome::QuotaDenied,
            ConsumptionStatus::NotConsumed,
        ),
        DenialKind::StorageCapacity => (
            AdmissionOutcome::CapacityDenied,
            ConsumptionStatus::NotConsumed,
        ),
    }
}

fn batch_relevant_check<'checks, 'policy, P: RateLimitPolicy + ?Sized>(
    checks: &'checks [Check<'policy, P>],
    decision: &BatchDecision,
) -> Option<&'checks Check<'policy, P>> {
    match decision.view() {
        BatchDecisionView::Allowed { decisions } if decisions.len() == 1 => checks.first(),
        BatchDecisionView::Allowed { .. } => None,
        BatchDecisionView::Denied { index, .. } | BatchDecisionView::ShadowDenied { index, .. } => {
            checks.get(index)
        }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{AdmissionObservation, AdmissionOperation, AdmissionOutcome, ConsumptionStatus};
    use crate::{
        BatchDecision, Check, Decision, Denial, FixedWindowPolicy, PolicyId, QuotaDenial,
        RateLimitPolicy, ScopeId, SubjectKey,
    };

    fn policy(id: &str) -> FixedWindowPolicy {
        FixedWindowPolicy::new(
            PolicyId::new(id).unwrap(),
            ScopeId::new("client").unwrap(),
            3,
            Duration::from_secs(60),
        )
        .unwrap()
    }

    fn assert_admission(
        admission: AdmissionObservation<'_>,
        operation: AdmissionOperation,
        batch_size: usize,
        policy: Option<&FixedWindowPolicy>,
        outcome: AdmissionOutcome,
        consumption: ConsumptionStatus,
        elapsed: Duration,
    ) {
        assert_eq!(admission.operation(), operation);
        assert_eq!(admission.batch_size(), batch_size);
        assert_eq!(admission.policy_id(), policy.map(RateLimitPolicy::id),);
        assert_eq!(admission.scope_id(), policy.map(RateLimitPolicy::scope),);
        assert_eq!(admission.outcome(), outcome);
        assert_eq!(admission.consumption(), consumption);
        assert_eq!(admission.elapsed(), elapsed);
    }

    #[test]
    fn check_decisions_keep_their_admission_classification() {
        let policy = policy("api.read");
        let check = Check::new(&policy, SubjectKey::from_digest([1; 32]));
        let elapsed = Duration::from_millis(7);
        let quota_denial = QuotaDenial::try_new(3, Duration::from_secs(1)).unwrap();
        let capacity_denial = Denial::storage_capacity(None);

        for (decision, outcome, consumption) in [
            (
                Decision::try_allowed(3, 2, Duration::from_secs(60)).unwrap(),
                AdmissionOutcome::Allowed,
                ConsumptionStatus::Consumed,
            ),
            (
                Decision::denied(quota_denial),
                AdmissionOutcome::QuotaDenied,
                ConsumptionStatus::NotConsumed,
            ),
            (
                Decision::shadow_denied(quota_denial),
                AdmissionOutcome::ShadowDenied,
                ConsumptionStatus::NotConsumed,
            ),
            (
                Decision::denied(capacity_denial),
                AdmissionOutcome::CapacityDenied,
                ConsumptionStatus::NotConsumed,
            ),
        ] {
            assert_admission(
                AdmissionObservation::from_check(&check, &decision, elapsed),
                AdmissionOperation::Check,
                1,
                Some(&policy),
                outcome,
                consumption,
                elapsed,
            );
        }
    }

    #[test]
    fn batch_decisions_keep_consumption_and_relevant_policy_semantics() {
        let first = policy("api.read");
        let second = policy("api.write");
        let checks = [
            Check::new(&first, SubjectKey::from_digest([1; 32])),
            Check::new(&second, SubjectKey::from_digest([2; 32])),
        ];
        let elapsed = Duration::from_millis(11);
        let allowed = Decision::try_allowed(3, 2, Duration::from_secs(60)).unwrap();
        let quota_denial = QuotaDenial::try_new(3, Duration::from_secs(1)).unwrap();
        let capacity_denial = Denial::storage_capacity(None);

        let empty: [Check<'_, FixedWindowPolicy>; 0] = [];
        assert_admission(
            AdmissionObservation::from_batch(
                &empty,
                &BatchDecision::try_allowed(Vec::new()).unwrap(),
                elapsed,
            ),
            AdmissionOperation::Batch,
            0,
            None,
            AdmissionOutcome::Allowed,
            ConsumptionStatus::NotConsumed,
            elapsed,
        );

        for (decision, policy, outcome, consumption) in [
            (
                BatchDecision::try_allowed(vec![allowed]).unwrap(),
                Some(&first),
                AdmissionOutcome::Allowed,
                ConsumptionStatus::Consumed,
            ),
            (
                BatchDecision::try_allowed(vec![allowed, allowed]).unwrap(),
                None,
                AdmissionOutcome::Allowed,
                ConsumptionStatus::Consumed,
            ),
            (
                BatchDecision::denied(1, quota_denial),
                Some(&second),
                AdmissionOutcome::QuotaDenied,
                ConsumptionStatus::NotConsumed,
            ),
            (
                BatchDecision::shadow_denied(0, quota_denial),
                Some(&first),
                AdmissionOutcome::ShadowDenied,
                ConsumptionStatus::NotConsumed,
            ),
            (
                BatchDecision::denied(1, capacity_denial),
                Some(&second),
                AdmissionOutcome::CapacityDenied,
                ConsumptionStatus::NotConsumed,
            ),
        ] {
            assert_admission(
                AdmissionObservation::from_batch(&checks, &decision, elapsed),
                AdmissionOperation::Batch,
                checks.len(),
                policy,
                outcome,
                consumption,
                elapsed,
            );
        }
    }
}
