use std::time::Duration;

use thiserror::Error;

use crate::MAX_LIMIT;

/// A backend-reported duration after which a denied check may be retried.
///
/// The exact duration remains available through [`RetryAfter::duration`].
/// [`RetryAfter::seconds`] rounds it up to the whole seconds that HTTP
/// `Retry-After` and similar headers require, so a header never invites a
/// retry before the backend would accept one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetryAfter {
    duration: Duration,
}

impl RetryAfter {
    /// Wraps a backend-measured retry duration.
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    /// Returns the exact backend-measured duration.
    pub const fn duration(self) -> Duration {
        self.duration
    }

    /// Returns the duration rounded up to whole seconds.
    ///
    /// Any fractional second rounds up. Values beyond the representable range
    /// saturate at [`u64::MAX`].
    pub const fn seconds(self) -> u64 {
        let seconds = self.duration.as_secs();
        if self.duration.subsec_nanos() == 0 {
            seconds
        } else {
            seconds.saturating_add(1)
        }
    }
}

impl From<Duration> for RetryAfter {
    fn from(duration: Duration) -> Self {
        Self::new(duration)
    }
}

/// An invalid decision or batch construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DecisionError {
    /// A quota capacity fell outside the portable policy range.
    #[error("decision capacity {capacity} is outside the portable policy range")]
    InvalidCapacity {
        /// Invalid capacity supplied by the caller.
        capacity: u64,
    },
    /// An allowed decision reported more available quota than its capacity.
    #[error("available quota {available} exceeds decision capacity {capacity}")]
    AvailableExceedsCapacity {
        /// Decision capacity.
        capacity: u64,
        /// Invalid available quota.
        available: u64,
    },
    /// A denied decision was supplied as a member of an allowed batch.
    #[error("allowed batch member {index} is not an allowed decision")]
    DeniedDecisionInAllowedBatch {
        /// Index of the invalid batch member.
        index: usize,
    },
}

/// Validated details for quota exhaustion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaDenial {
    capacity: u64,
    retry_after: RetryAfter,
}

impl QuotaDenial {
    /// Constructs quota-denial details, panicking if capacity is invalid.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero or exceeds [`MAX_LIMIT`].
    pub const fn new(capacity: u64, retry_after: Duration) -> Self {
        match Self::try_new(capacity, retry_after) {
            Ok(denial) => denial,
            Err(_) => panic!("invalid quota-denial capacity"),
        }
    }

    /// Constructs validated quota-denial details.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionError::InvalidCapacity`] when `capacity` is zero or
    /// exceeds [`MAX_LIMIT`].
    pub const fn try_new(capacity: u64, retry_after: Duration) -> Result<Self, DecisionError> {
        if capacity == 0 || capacity > MAX_LIMIT {
            return Err(DecisionError::InvalidCapacity { capacity });
        }
        Ok(Self {
            capacity,
            retry_after: RetryAfter::new(retry_after),
        })
    }

    /// Returns the maximum immediately available policy allowance.
    pub const fn capacity(self) -> u64 {
        self.capacity
    }

    /// Returns the duration until the rejected cost can be retried.
    pub const fn retry_after(self) -> RetryAfter {
        self.retry_after
    }
}

/// A read-only, discriminated view of a [`Denial`].
///
/// Each variant names one denial reason and carries exactly the metadata that
/// reason provides. There is no reason-agnostic accessor: consumers match
/// every variant, so a new reason is a breaking change that fails to compile
/// in every consumer instead of landing in a fallback arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialView {
    /// Consuming the requested cost would exceed the configured quota.
    QuotaExceeded(QuotaDenial),
    /// A bounded backend could not safely allocate storage for a new key.
    StorageCapacity {
        /// Duration until the backend's earliest known expiry, when known.
        retry_after: Option<RetryAfter>,
    },
}

/// Structured details for a denied check.
///
/// A quota denial always contains its policy capacity and the duration until
/// the requested cost can be retried. A storage-capacity denial may contain
/// the duration until the backend's earliest known expiry, when one is
/// available.
///
/// Process-local backends can measure the duration at evaluation time exactly.
/// Distributed backends may return a safe upper bound measured with their
/// authoritative clock, which can overstate the duration at the caller by
/// commit and transport time.
///
/// With the `serde` feature, this is an object tagged by `reason`. Durations
/// use Serde's exact `{ "secs": ..., "nanos": ... }` representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Denial {
    view: DenialView,
}

impl Denial {
    /// Constructs a quota-exhaustion denial from validated details.
    pub const fn quota_exceeded(denial: QuotaDenial) -> Self {
        Self {
            view: DenialView::QuotaExceeded(denial),
        }
    }

    /// Constructs a storage-capacity denial.
    pub const fn storage_capacity(retry_after: Option<Duration>) -> Self {
        let retry_after = match retry_after {
            Some(duration) => Some(RetryAfter::new(duration)),
            None => None,
        };
        Self {
            view: DenialView::StorageCapacity { retry_after },
        }
    }

    /// Returns a read-only view that discriminates every denial reason.
    pub const fn view(&self) -> DenialView {
        self.view
    }
}

impl From<QuotaDenial> for Denial {
    fn from(denial: QuotaDenial) -> Self {
        Self::quota_exceeded(denial)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Allowance {
    capacity: u64,
    available: u64,
    replenishes_after: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Allowed(Allowance),
    Denied(Denial),
    ShadowDenied(QuotaDenial),
}

/// A read-only, discriminated view of a [`Decision`].
///
/// Each variant exposes exactly the metadata that is valid for that outcome.
/// Shadow denials contain only quota details because storage-capacity denials
/// are always enforced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionView {
    /// Quota was consumed and the request may proceed.
    Allowed {
        /// Maximum immediately available policy allowance.
        capacity: u64,
        /// Allowance available after consuming this check.
        available: u64,
        /// Time until the policy's full capacity is next available.
        replenishes_after: Duration,
    },
    /// The application must enforce this denial.
    Denied {
        /// Backend-reported denial reason and details.
        denial: DenialView,
    },
    /// Quota was exceeded in shadow mode, so the request may proceed.
    ShadowDenied {
        /// Validated quota-exhaustion details.
        denial: QuotaDenial,
    },
}

/// The outcome of evaluating one check.
///
/// Allowed outcomes report immediately available allowance after the check
/// and the backend-reported time until full capacity is replenished. Denied
/// outcomes carry a [`Denial`].
///
/// With the `serde` feature, this is an object tagged by `outcome`. Invalid
/// allowed metadata, such as `available` exceeding `capacity`, is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    outcome: Outcome,
}

impl Decision {
    /// Constructs an allowed decision, panicking if its metadata is invalid.
    ///
    /// Backend implementations that cannot prove their metadata invariants
    /// should use [`Decision::try_allowed`] instead.
    ///
    /// # Panics
    ///
    /// Panics when the capacity is outside the portable policy range or
    /// `available` exceeds `capacity`.
    pub const fn allowed(capacity: u64, available: u64, replenishes_after: Duration) -> Self {
        match Self::try_allowed(capacity, available, replenishes_after) {
            Ok(decision) => decision,
            Err(_) => panic!("invalid allowed decision metadata"),
        }
    }

    /// Constructs an allowed decision.
    ///
    /// Storage backends should pass the available allowance after consuming
    /// the check's cost.
    ///
    /// # Errors
    ///
    /// Returns an error when the capacity is outside the portable policy range
    /// or `available` exceeds `capacity`.
    pub const fn try_allowed(
        capacity: u64,
        available: u64,
        replenishes_after: Duration,
    ) -> Result<Self, DecisionError> {
        if capacity == 0 || capacity > MAX_LIMIT {
            return Err(DecisionError::InvalidCapacity { capacity });
        }
        if available > capacity {
            return Err(DecisionError::AvailableExceedsCapacity {
                capacity,
                available,
            });
        }
        Ok(Self {
            outcome: Outcome::Allowed(Allowance {
                capacity,
                available,
                replenishes_after,
            }),
        })
    }

    /// Constructs a denied decision.
    pub fn denied(denial: impl Into<Denial>) -> Self {
        Self {
            outcome: Outcome::Denied(denial.into()),
        }
    }

    /// Constructs an enforced quota denial.
    pub const fn quota_denied(denial: QuotaDenial) -> Self {
        Self {
            outcome: Outcome::Denied(Denial::quota_exceeded(denial)),
        }
    }

    /// Constructs a shadow quota denial.
    pub const fn shadow_denied(denial: QuotaDenial) -> Self {
        Self {
            outcome: Outcome::ShadowDenied(denial),
        }
    }

    /// Returns a read-only view that discriminates every valid outcome.
    pub const fn view(&self) -> DecisionView {
        match self.outcome {
            Outcome::Allowed(allowance) => DecisionView::Allowed {
                capacity: allowance.capacity,
                available: allowance.available,
                replenishes_after: allowance.replenishes_after,
            },
            Outcome::Denied(denial) => DecisionView::Denied {
                denial: denial.view(),
            },
            Outcome::ShadowDenied(denial) => DecisionView::ShadowDenied { denial },
        }
    }

    /// Returns whether the application may proceed.
    ///
    /// This includes both consumed allowed decisions and quota denials from a
    /// shadow policy.
    pub const fn permits_request(&self) -> bool {
        !matches!(self.outcome, Outcome::Denied(_))
    }

    /// Returns whether this check encountered quota or capacity denial.
    pub const fn would_deny(&self) -> bool {
        !matches!(self.outcome, Outcome::Allowed(_))
    }

    /// Returns whether this decision must be enforced.
    pub const fn is_enforced_denial(&self) -> bool {
        matches!(self.outcome, Outcome::Denied(_))
    }

    /// Returns whether quota was exceeded in shadow mode.
    pub const fn is_shadow_denied(&self) -> bool {
        matches!(self.outcome, Outcome::ShadowDenied(_))
    }

    const fn was_consumed(&self) -> bool {
        matches!(self.outcome, Outcome::Allowed(_))
    }
}

/// The atomic outcome of evaluating checks in caller-supplied order.
///
/// An allowed batch contains one allowed decision for each input check, in the
/// same order. A denied batch reports the original input index that failed.
/// Backends must not consume any check when returning an enforced denial.
///
/// With the `serde` feature, this is an object tagged by `outcome`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchDecision {
    outcome: BatchOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BatchOutcome {
    Allowed(Vec<Decision>),
    Denied { index: usize, denial: Denial },
    ShadowDenied { index: usize, denial: QuotaDenial },
}

/// A read-only, discriminated view of a [`BatchDecision`].
///
/// Allowed decisions remain in caller order. Denial indices always refer to
/// the original caller-supplied input order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchDecisionView<'a> {
    /// Every check was allowed and consumed atomically.
    Allowed {
        /// Allowed decisions in caller order.
        decisions: &'a [Decision],
    },
    /// The application must enforce the named input's denial.
    Denied {
        /// Index of the denied input in caller order.
        index: usize,
        /// Backend-reported denial reason and details.
        denial: DenialView,
    },
    /// The named input exceeded quota in shadow mode.
    ShadowDenied {
        /// Index of the shadow-denied input in caller order.
        index: usize,
        /// Validated quota-exhaustion details.
        denial: QuotaDenial,
    },
}

impl BatchDecision {
    /// Constructs an allowed batch, panicking if any member is a denial.
    ///
    /// # Panics
    ///
    /// Panics when a member is an enforced or shadow denial.
    pub fn allowed(decisions: Vec<Decision>) -> Self {
        Self::try_allowed(decisions).expect("allowed batches can contain only allowed decisions")
    }

    /// Constructs an allowed batch from consumed allowed decisions.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionError::DeniedDecisionInAllowedBatch`] when a member is
    /// an enforced or shadow denial.
    pub fn try_allowed(decisions: Vec<Decision>) -> Result<Self, DecisionError> {
        if let Some(index) = decisions
            .iter()
            .position(|decision| !decision.was_consumed())
        {
            return Err(DecisionError::DeniedDecisionInAllowedBatch { index });
        }
        Ok(Self {
            outcome: BatchOutcome::Allowed(decisions),
        })
    }

    /// Constructs an enforced batch denial.
    pub fn denied(index: usize, denial: impl Into<Denial>) -> Self {
        Self {
            outcome: BatchOutcome::Denied {
                index,
                denial: denial.into(),
            },
        }
    }

    /// Constructs a shadow batch denial.
    pub const fn shadow_denied(index: usize, denial: QuotaDenial) -> Self {
        Self {
            outcome: BatchOutcome::ShadowDenied { index, denial },
        }
    }

    /// Returns a read-only view that discriminates every valid outcome.
    pub fn view(&self) -> BatchDecisionView<'_> {
        match &self.outcome {
            BatchOutcome::Allowed(decisions) => BatchDecisionView::Allowed { decisions },
            BatchOutcome::Denied { index, denial } => BatchDecisionView::Denied {
                index: *index,
                denial: denial.view(),
            },
            BatchOutcome::ShadowDenied { index, denial } => BatchDecisionView::ShadowDenied {
                index: *index,
                denial: *denial,
            },
        }
    }

    /// Returns whether the application may proceed.
    pub const fn permits_request(&self) -> bool {
        !matches!(self.outcome, BatchOutcome::Denied { .. })
    }

    /// Returns whether evaluation encountered quota or capacity denial.
    pub const fn would_deny(&self) -> bool {
        !matches!(self.outcome, BatchOutcome::Allowed(_))
    }

    /// Returns whether the application must reject the operation.
    pub const fn is_enforced_denial(&self) -> bool {
        matches!(self.outcome, BatchOutcome::Denied { .. })
    }

    /// Returns whether quota was exceeded in shadow mode.
    pub const fn is_shadow_denied(&self) -> bool {
        matches!(self.outcome, BatchOutcome::ShadowDenied { .. })
    }

    /// Consumes an allowed batch and returns its decisions.
    ///
    /// # Errors
    ///
    /// Returns the unchanged batch when it is an enforced or shadow denial.
    pub fn try_into_allowed(self) -> Result<Vec<Decision>, Self> {
        match self.outcome {
            BatchOutcome::Allowed(decisions) => Ok(decisions),
            BatchOutcome::Denied { .. } | BatchOutcome::ShadowDenied { .. } => Err(self),
        }
    }

    /// Converts a batch-of-one outcome into its single-check decision.
    ///
    /// Returns the original batch when an allowed result does not contain
    /// exactly one allowed decision or a denied result names an index other
    /// than zero.
    ///
    /// # Errors
    ///
    /// Returns the unchanged batch when it is not a valid batch-of-one result.
    pub fn try_into_single_decision(self) -> Result<Decision, Self> {
        match self.outcome {
            BatchOutcome::Allowed(decisions) if matches!(decisions.as_slice(), [_]) => {
                Ok(decisions[0])
            }
            BatchOutcome::Denied { index: 0, denial } => Ok(Decision::denied(denial)),
            BatchOutcome::ShadowDenied { index: 0, denial } => Ok(Decision::shadow_denied(denial)),
            outcome => Err(Self { outcome }),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
enum DenialRef {
    QuotaExceeded {
        capacity: u64,
        retry_after: Duration,
    },
    StorageCapacity {
        retry_after: Option<Duration>,
    },
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
enum DenialWire {
    QuotaExceeded {
        capacity: u64,
        retry_after: Duration,
    },
    StorageCapacity {
        retry_after: Option<Duration>,
    },
}

#[cfg(feature = "serde")]
impl serde::Serialize for Denial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match self.view {
            DenialView::QuotaExceeded(denial) => DenialRef::QuotaExceeded {
                capacity: denial.capacity(),
                retry_after: denial.retry_after().duration(),
            },
            DenialView::StorageCapacity { retry_after } => DenialRef::StorageCapacity {
                retry_after: retry_after.map(RetryAfter::duration),
            },
        };
        serde::Serialize::serialize(&wire, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Denial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = <DenialWire as serde::Deserialize>::deserialize(deserializer)?;
        match wire {
            DenialWire::QuotaExceeded {
                capacity,
                retry_after,
            } => QuotaDenial::try_new(capacity, retry_after)
                .map(Self::quota_exceeded)
                .map_err(serde::de::Error::custom),
            DenialWire::StorageCapacity { retry_after } => Ok(Self::storage_capacity(retry_after)),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum DecisionRef<'a> {
    Allowed {
        capacity: u64,
        available: u64,
        replenishes_after: Duration,
    },
    Denied {
        denial: &'a Denial,
    },
    ShadowDenied {
        denial: Denial,
    },
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum DecisionWire {
    Allowed {
        capacity: u64,
        available: u64,
        replenishes_after: Duration,
    },
    Denied {
        denial: Denial,
    },
    ShadowDenied {
        denial: Denial,
    },
}

#[cfg(feature = "serde")]
impl serde::Serialize for Decision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match &self.outcome {
            Outcome::Allowed(allowance) => DecisionRef::Allowed {
                capacity: allowance.capacity,
                available: allowance.available,
                replenishes_after: allowance.replenishes_after,
            },
            Outcome::Denied(denial) => DecisionRef::Denied { denial },
            Outcome::ShadowDenied(denial) => DecisionRef::ShadowDenied {
                denial: Denial::quota_exceeded(*denial),
            },
        };
        serde::Serialize::serialize(&wire, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Decision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = <DecisionWire as serde::Deserialize>::deserialize(deserializer)?;
        match wire {
            DecisionWire::Allowed {
                capacity,
                available,
                replenishes_after,
            } => Self::try_allowed(capacity, available, replenishes_after)
                .map_err(serde::de::Error::custom),
            DecisionWire::Denied { denial } => Ok(Self::denied(denial)),
            DecisionWire::ShadowDenied { denial } => match denial.view() {
                DenialView::QuotaExceeded(denial) => Ok(Self::shadow_denied(denial)),
                DenialView::StorageCapacity { .. } => Err(serde::de::Error::custom(
                    "only quota exhaustion can be shadowed",
                )),
            },
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum BatchDecisionRef<'a> {
    Allowed { decisions: &'a [Decision] },
    Denied { index: usize, denial: &'a Denial },
    ShadowDenied { index: usize, denial: Denial },
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum BatchDecisionWire {
    Allowed { decisions: Vec<Decision> },
    Denied { index: usize, denial: Denial },
    ShadowDenied { index: usize, denial: Denial },
}

#[cfg(feature = "serde")]
impl serde::Serialize for BatchDecision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match &self.outcome {
            BatchOutcome::Allowed(decisions) => BatchDecisionRef::Allowed { decisions },
            BatchOutcome::Denied { index, denial } => BatchDecisionRef::Denied {
                index: *index,
                denial,
            },
            BatchOutcome::ShadowDenied { index, denial } => BatchDecisionRef::ShadowDenied {
                index: *index,
                denial: Denial::quota_exceeded(*denial),
            },
        };
        serde::Serialize::serialize(&wire, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BatchDecision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = <BatchDecisionWire as serde::Deserialize>::deserialize(deserializer)?;
        match wire {
            BatchDecisionWire::Allowed { decisions } => {
                Self::try_allowed(decisions).map_err(serde::de::Error::custom)
            }
            BatchDecisionWire::Denied { index, denial } => Ok(Self::denied(index, denial)),
            BatchDecisionWire::ShadowDenied { index, denial } => match denial.view() {
                DenialView::QuotaExceeded(denial) => Ok(Self::shadow_denied(index, denial)),
                DenialView::StorageCapacity { .. } => Err(serde::de::Error::custom(
                    "only quota exhaustion can be shadowed",
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        BatchDecision, BatchDecisionView, Decision, DecisionError, DecisionView, Denial,
        DenialView, QuotaDenial, RetryAfter,
    };

    fn allowed(capacity: u64, available: u64, replenishes_after: Duration) -> Decision {
        Decision::try_allowed(capacity, available, replenishes_after).unwrap()
    }

    fn quota(capacity: u64, retry_after: Duration) -> QuotaDenial {
        QuotaDenial::try_new(capacity, retry_after).unwrap()
    }

    #[test]
    fn allowed_decision_exposes_available_and_replenishment() {
        let decision = allowed(8, 7, Duration::from_millis(59_999));

        assert!(decision.permits_request());
        assert!(!decision.is_enforced_denial());
        assert!(!decision.would_deny());
        assert_eq!(
            decision.view(),
            DecisionView::Allowed {
                capacity: 8,
                available: 7,
                replenishes_after: Duration::from_millis(59_999),
            }
        );
    }

    #[test]
    fn quota_denial_exposes_exact_and_ceiling_retry_duration() {
        let quota = quota(8, Duration::from_millis(1_001));
        let decision = Decision::denied(quota);

        assert!(decision.is_enforced_denial());
        assert_eq!(decision, Decision::quota_denied(quota));
        assert_eq!(
            decision.view(),
            DecisionView::Denied {
                denial: DenialView::QuotaExceeded(quota),
            }
        );
        assert_eq!(quota.capacity(), 8);
        assert_eq!(quota.retry_after().duration(), Duration::from_millis(1_001));
        assert_eq!(quota.retry_after().seconds(), 2);
    }

    #[test]
    fn retry_after_seconds_preserves_exact_seconds() {
        assert_eq!(RetryAfter::new(Duration::ZERO).seconds(), 0);
        assert_eq!(RetryAfter::new(Duration::from_secs(3)).seconds(), 3);
        assert_eq!(RetryAfter::new(Duration::from_nanos(1)).seconds(), 1);
    }

    #[test]
    fn retry_after_seconds_saturates_without_losing_exact_duration() {
        let duration = Duration::new(u64::MAX, 1);
        let retry_after = RetryAfter::from(duration);

        assert_eq!(retry_after.duration(), duration);
        assert_eq!(retry_after.seconds(), u64::MAX);
    }

    #[test]
    fn storage_capacity_retry_can_be_unknown() {
        let unknown = Denial::storage_capacity(None);
        let known = Denial::storage_capacity(Some(Duration::from_millis(1)));

        assert_eq!(
            unknown.view(),
            DenialView::StorageCapacity { retry_after: None }
        );
        assert_eq!(
            known.view(),
            DenialView::StorageCapacity {
                retry_after: Some(RetryAfter::new(Duration::from_millis(1))),
            }
        );
        assert_eq!(
            Decision::denied(unknown).view(),
            DecisionView::Denied {
                denial: unknown.view(),
            }
        );
    }

    #[test]
    fn batch_of_one_converts_to_a_single_decision() {
        let allowed = allowed(8, 7, Duration::from_mins(1));
        let denied = quota(8, Duration::from_mins(1));

        assert_eq!(
            BatchDecision::try_allowed(vec![allowed])
                .unwrap()
                .try_into_single_decision(),
            Ok(allowed)
        );
        assert_eq!(
            BatchDecision::denied(0, denied).try_into_single_decision(),
            Ok(Decision::denied(denied))
        );
    }

    #[test]
    fn malformed_batch_of_one_is_rejected() {
        let decision = allowed(8, 7, Duration::from_mins(1));
        let denial = quota(8, Duration::from_mins(1));

        assert!(
            BatchDecision::try_allowed(Vec::new())
                .unwrap()
                .try_into_single_decision()
                .is_err()
        );
        assert!(
            BatchDecision::try_allowed(vec![decision, decision])
                .unwrap()
                .try_into_single_decision()
                .is_err()
        );
        assert_eq!(
            BatchDecision::try_allowed(vec![Decision::denied(denial)]),
            Err(DecisionError::DeniedDecisionInAllowedBatch { index: 0 })
        );
        assert!(
            BatchDecision::denied(1, denial)
                .try_into_single_decision()
                .is_err()
        );
    }

    #[test]
    fn allowed_batch_rejects_shadow_denied_member() {
        let shadow = Decision::shadow_denied(quota(8, Duration::from_secs(30)));
        assert!(shadow.permits_request());

        assert_eq!(
            BatchDecision::try_allowed(vec![allowed(8, 7, Duration::from_mins(1)), shadow]),
            Err(DecisionError::DeniedDecisionInAllowedBatch { index: 1 })
        );
    }

    #[test]
    fn shadow_denial_permits_the_request_without_claiming_consumption() {
        let denial = quota(8, Duration::from_millis(30_001));
        let decision = Decision::shadow_denied(denial);

        assert!(decision.permits_request());
        assert!(!decision.is_enforced_denial());
        assert!(decision.would_deny());
        assert!(decision.is_shadow_denied());
        assert_eq!(decision.view(), DecisionView::ShadowDenied { denial });
        assert_eq!(denial.retry_after().seconds(), 31);
        assert_eq!(
            BatchDecision::shadow_denied(0, denial).try_into_single_decision(),
            Ok(decision)
        );
    }

    #[test]
    fn decision_views_outlive_the_decision() {
        fn view_of_temporary() -> DecisionView {
            Decision::denied(Denial::storage_capacity(None)).view()
        }

        assert_eq!(
            view_of_temporary(),
            DecisionView::Denied {
                denial: DenialView::StorageCapacity { retry_after: None },
            }
        );
    }

    #[test]
    fn batch_views_preserve_allowed_order_and_denial_indices() {
        let first = allowed(8, 7, Duration::from_mins(1));
        let second = allowed(4, 2, Duration::from_secs(30));
        let allowed_batch = BatchDecision::allowed(vec![first, second]);
        assert_eq!(
            allowed_batch.view(),
            BatchDecisionView::Allowed {
                decisions: &[first, second],
            }
        );

        let quota = quota(8, Duration::from_secs(30));
        let denied = BatchDecision::denied(1, quota);
        assert_eq!(
            denied.view(),
            BatchDecisionView::Denied {
                index: 1,
                denial: DenialView::QuotaExceeded(quota),
            }
        );

        let capacity = BatchDecision::denied(2, Denial::storage_capacity(None));
        assert_eq!(
            capacity.view(),
            BatchDecisionView::Denied {
                index: 2,
                denial: DenialView::StorageCapacity { retry_after: None },
            }
        );

        let shadow = BatchDecision::shadow_denied(2, quota);
        assert_eq!(
            shadow.view(),
            BatchDecisionView::ShadowDenied {
                index: 2,
                denial: quota,
            }
        );
        assert_eq!(shadow.clone().try_into_single_decision(), Err(shadow));
    }

    #[test]
    fn invalid_decision_metadata_is_rejected_at_construction() {
        assert_eq!(
            QuotaDenial::try_new(0, Duration::ZERO),
            Err(DecisionError::InvalidCapacity { capacity: 0 })
        );
        assert_eq!(
            Decision::try_allowed(8, 9, Duration::ZERO),
            Err(DecisionError::AvailableExceedsCapacity {
                capacity: 8,
                available: 9,
            })
        );
    }
}
