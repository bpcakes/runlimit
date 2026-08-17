use std::time::Duration;

use thiserror::Error;

use crate::MAX_LIMIT;

/// Why a check was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DenialKind {
    /// Consuming the requested cost would exceed the configured quota.
    QuotaExceeded,
    /// A bounded backend could not safely allocate storage for a new key.
    StorageCapacity,
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
    retry_after: Duration,
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
            retry_after,
        })
    }

    /// Returns the maximum immediately available policy allowance.
    pub const fn capacity(self) -> u64 {
        self.capacity
    }

    /// Returns the duration until the rejected cost can be retried.
    pub const fn retry_after(self) -> Duration {
        self.retry_after
    }
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
    reason: DenialReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DenialReason {
    QuotaExceeded(QuotaDenial),
    StorageCapacity { retry_after: Option<Duration> },
}

impl Denial {
    /// Constructs a quota-exhaustion denial from validated details.
    pub const fn quota_exceeded(denial: QuotaDenial) -> Self {
        Self {
            reason: DenialReason::QuotaExceeded(denial),
        }
    }

    /// Constructs a storage-capacity denial.
    pub const fn storage_capacity(retry_after: Option<Duration>) -> Self {
        Self {
            reason: DenialReason::StorageCapacity { retry_after },
        }
    }

    /// Returns the denial category.
    pub const fn kind(&self) -> DenialKind {
        match self.reason {
            DenialReason::QuotaExceeded(_) => DenialKind::QuotaExceeded,
            DenialReason::StorageCapacity { .. } => DenialKind::StorageCapacity,
        }
    }

    /// Returns quota-exhaustion details, when this is a quota denial.
    pub const fn quota(&self) -> Option<QuotaDenial> {
        match self.reason {
            DenialReason::QuotaExceeded(denial) => Some(denial),
            DenialReason::StorageCapacity { .. } => None,
        }
    }

    /// Returns the configured quota capacity, when this is a quota denial.
    pub const fn capacity(&self) -> Option<u64> {
        match self.quota() {
            Some(denial) => Some(denial.capacity()),
            None => None,
        }
    }

    /// Returns the backend-reported duration after which the caller may retry,
    /// if known.
    pub const fn retry_after(&self) -> Option<Duration> {
        match self.reason {
            DenialReason::QuotaExceeded(denial) => Some(denial.retry_after()),
            DenialReason::StorageCapacity { retry_after } => retry_after,
        }
    }

    /// Returns a whole-second `Retry-After` value rounded up, if known.
    ///
    /// The underlying [`Duration`] remains available through
    /// [`Denial::retry_after`]. Values beyond the representable range saturate
    /// at [`u64::MAX`].
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self.retry_after() {
            Some(duration) => Some(ceil_seconds(duration)),
            None => None,
        }
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
    ShadowDenied(Denial),
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
            outcome: Outcome::ShadowDenied(Denial::quota_exceeded(denial)),
        }
    }

    /// Returns whether the application may proceed.
    ///
    /// This includes both consumed allowed decisions and quota denials from a
    /// shadow policy.
    pub const fn is_allowed(&self) -> bool {
        self.permits_request()
    }

    /// Returns whether the application must reject the operation.
    pub const fn is_denied(&self) -> bool {
        self.is_enforced_denial()
    }

    /// Returns whether the application may proceed.
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

    /// Returns the configured capacity when it is meaningful for this outcome.
    ///
    /// Allowed decisions and quota denials have a capacity. Storage-capacity
    /// denials do not.
    pub const fn capacity(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Allowed(allowance) => Some(allowance.capacity),
            Outcome::Denied(denial) | Outcome::ShadowDenied(denial) => denial.capacity(),
        }
    }

    /// Returns the immediately available allowance after a consumed check.
    pub const fn available(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Allowed(allowance) => Some(allowance.available),
            Outcome::Denied(_) | Outcome::ShadowDenied(_) => None,
        }
    }

    /// Returns when an allowed decision's full capacity is next available.
    pub const fn replenishes_after(&self) -> Option<Duration> {
        match self.outcome {
            Outcome::Allowed(allowance) => Some(allowance.replenishes_after),
            Outcome::Denied(_) | Outcome::ShadowDenied(_) => None,
        }
    }

    /// Returns the backend-reported duration after which a denied check may
    /// retry.
    pub const fn retry_after(&self) -> Option<Duration> {
        match self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) | Outcome::ShadowDenied(denial) => denial.retry_after(),
        }
    }

    /// Returns a whole-second `Retry-After` value rounded up, if known.
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) | Outcome::ShadowDenied(denial) => denial.retry_after_seconds(),
        }
    }

    /// Returns denial details for a denied check.
    pub const fn denial(&self) -> Option<&Denial> {
        match &self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) | Outcome::ShadowDenied(denial) => Some(denial),
        }
    }

    /// Returns quota-denial details for an enforced or shadow quota denial.
    pub const fn quota_denial(&self) -> Option<QuotaDenial> {
        match self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) | Outcome::ShadowDenied(denial) => denial.quota(),
        }
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
    ShadowDenied { index: usize, denial: Denial },
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
            outcome: BatchOutcome::ShadowDenied {
                index,
                denial: Denial::quota_exceeded(denial),
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

    /// Returns allowed decisions in caller order, when the batch was allowed.
    pub fn allowed_decisions(&self) -> Option<&[Decision]> {
        match &self.outcome {
            BatchOutcome::Allowed(decisions) => Some(decisions),
            BatchOutcome::Denied { .. } | BatchOutcome::ShadowDenied { .. } => None,
        }
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

    /// Returns the input index that caused a denial, when any.
    pub const fn denied_index(&self) -> Option<usize> {
        match self.outcome {
            BatchOutcome::Allowed(_) => None,
            BatchOutcome::Denied { index, .. } | BatchOutcome::ShadowDenied { index, .. } => {
                Some(index)
            }
        }
    }

    /// Returns denial details for an enforced or shadow denial.
    pub const fn denial(&self) -> Option<&Denial> {
        match &self.outcome {
            BatchOutcome::Allowed(_) => None,
            BatchOutcome::Denied { denial, .. } | BatchOutcome::ShadowDenied { denial, .. } => {
                Some(denial)
            }
        }
    }

    /// Returns quota-denial details for an enforced or shadow quota denial.
    pub const fn quota_denial(&self) -> Option<QuotaDenial> {
        match self.outcome {
            BatchOutcome::Allowed(_) => None,
            BatchOutcome::Denied { denial, .. } | BatchOutcome::ShadowDenied { denial, .. } => {
                denial.quota()
            }
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
            BatchOutcome::ShadowDenied { index: 0, denial } => match denial.quota() {
                Some(denial) => Ok(Decision::shadow_denied(denial)),
                None => Err(Self {
                    outcome: BatchOutcome::ShadowDenied { index: 0, denial },
                }),
            },
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
        let wire = match self.reason {
            DenialReason::QuotaExceeded(denial) => DenialRef::QuotaExceeded {
                capacity: denial.capacity(),
                retry_after: denial.retry_after(),
            },
            DenialReason::StorageCapacity { retry_after } => {
                DenialRef::StorageCapacity { retry_after }
            }
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
        denial: &'a Denial,
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
            Outcome::ShadowDenied(denial) => DecisionRef::ShadowDenied { denial },
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
            DecisionWire::ShadowDenied { denial } => denial
                .quota()
                .map(Self::shadow_denied)
                .ok_or_else(|| serde::de::Error::custom("only quota exhaustion can be shadowed")),
        }
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum BatchDecisionRef<'a> {
    Allowed { decisions: &'a [Decision] },
    Denied { index: usize, denial: &'a Denial },
    ShadowDenied { index: usize, denial: &'a Denial },
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
                denial,
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
            BatchDecisionWire::ShadowDenied { index, denial } => denial
                .quota()
                .map(|denial| Self::shadow_denied(index, denial))
                .ok_or_else(|| serde::de::Error::custom("only quota exhaustion can be shadowed")),
        }
    }
}

const fn ceil_seconds(duration: Duration) -> u64 {
    let seconds = duration.as_secs();
    if duration.subsec_nanos() == 0 {
        seconds
    } else {
        seconds.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BatchDecision, Decision, DecisionError, Denial, DenialKind, QuotaDenial};

    fn allowed(capacity: u64, available: u64, replenishes_after: Duration) -> Decision {
        Decision::try_allowed(capacity, available, replenishes_after).unwrap()
    }

    fn quota(capacity: u64, retry_after: Duration) -> QuotaDenial {
        QuotaDenial::try_new(capacity, retry_after).unwrap()
    }

    #[test]
    fn allowed_decision_exposes_available_and_replenishment() {
        let decision = allowed(8, 7, Duration::from_millis(59_999));

        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert_eq!(decision.capacity(), Some(8));
        assert_eq!(decision.available(), Some(7));
        assert_eq!(
            decision.replenishes_after(),
            Some(Duration::from_millis(59_999))
        );
        assert_eq!(decision.retry_after(), None);
        assert_eq!(decision.denial(), None);
    }

    #[test]
    fn quota_denial_exposes_exact_and_ceiling_retry_duration() {
        let quota = quota(8, Duration::from_millis(1_001));
        let denial = Denial::quota_exceeded(quota);
        let decision = Decision::denied(denial);

        assert!(decision.is_denied());
        assert_eq!(decision.capacity(), Some(8));
        assert_eq!(decision.available(), None);
        assert_eq!(decision.replenishes_after(), None);
        assert_eq!(decision.retry_after(), Some(Duration::from_millis(1_001)));
        assert_eq!(decision.retry_after_seconds(), Some(2));
        assert_eq!(decision.denial(), Some(&denial));
        assert_eq!(denial.kind(), DenialKind::QuotaExceeded);
        assert_eq!(denial.quota(), Some(quota));
    }

    #[test]
    fn retry_after_seconds_preserves_exact_seconds() {
        let denial = Denial::quota_exceeded(quota(1, Duration::from_secs(3)));

        assert_eq!(denial.retry_after_seconds(), Some(3));
    }

    #[test]
    fn retry_after_seconds_saturates_without_losing_exact_duration() {
        let duration = Duration::new(u64::MAX, 1);
        let denial = Denial::quota_exceeded(quota(1, duration));

        assert_eq!(denial.retry_after(), Some(duration));
        assert_eq!(denial.retry_after_seconds(), Some(u64::MAX));
    }

    #[test]
    fn storage_capacity_retry_can_be_unknown() {
        let denial = Denial::storage_capacity(None);
        let decision = Decision::denied(denial);

        assert_eq!(denial.kind(), DenialKind::StorageCapacity);
        assert_eq!(denial.retry_after(), None);
        assert_eq!(denial.retry_after_seconds(), None);
        assert_eq!(decision.capacity(), None);
        assert_eq!(decision.retry_after(), None);
    }

    #[test]
    fn batch_of_one_converts_to_a_single_decision() {
        let allowed = allowed(8, 7, Duration::from_secs(60));
        let denied = quota(8, Duration::from_secs(60));

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
        let decision = allowed(8, 7, Duration::from_secs(60));
        let denial = quota(8, Duration::from_secs(60));

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
    fn shadow_denial_permits_the_request_without_claiming_consumption() {
        let denial = quota(8, Duration::from_secs(30));
        let decision = Decision::shadow_denied(denial);

        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(decision.permits_request());
        assert!(decision.would_deny());
        assert!(decision.is_shadow_denied());
        assert_eq!(decision.available(), None);
        assert_eq!(decision.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(
            BatchDecision::shadow_denied(0, denial).try_into_single_decision(),
            Ok(decision)
        );
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
