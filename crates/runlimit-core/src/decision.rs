use std::{num::NonZeroUsize, time::Duration};

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
    /// An allowance reported more available quota than its capacity.
    #[error("available quota {available} exceeds decision capacity {capacity}")]
    AvailableExceedsCapacity {
        /// Decision capacity.
        capacity: u64,
        /// Invalid available quota.
        available: u64,
    },
    /// A batch denial named an input index at or beyond its batch size.
    #[error("denied batch index {index} is out of range for a batch of {batch_size} checks")]
    DeniedIndexOutOfRange {
        /// Index of the denied input supplied by the caller.
        index: usize,
        /// Batch size supplied by the caller.
        batch_size: usize,
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

/// Validated allowance metadata for an allowed check.
///
/// An allowance reports the policy's maximum immediately available capacity,
/// the allowance still available after this check consumed its cost, and the
/// backend-reported time until full capacity is next available. `available`
/// never exceeds `capacity`, and `capacity` lies within the portable policy
/// range, so every constructible allowance is valid.
///
/// With the `serde` feature, this is an object with `capacity`, `available`,
/// and `replenishes_after` fields. Deserialization applies the same
/// validation as [`Allowance::try_new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allowance {
    capacity: u64,
    available: u64,
    replenishes_after: Duration,
}

impl Allowance {
    /// Constructs an allowance, panicking if its metadata is invalid.
    ///
    /// Backend implementations that cannot prove their metadata invariants
    /// should use [`Allowance::try_new`] instead.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is outside the portable policy range or
    /// `available` exceeds `capacity`.
    pub const fn new(capacity: u64, available: u64, replenishes_after: Duration) -> Self {
        match Self::try_new(capacity, available, replenishes_after) {
            Ok(allowance) => allowance,
            Err(_) => panic!("invalid allowance metadata"),
        }
    }

    /// Constructs a validated allowance.
    ///
    /// Storage backends should pass the allowance available after consuming
    /// the check's cost.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionError::InvalidCapacity`] when `capacity` is zero or
    /// exceeds [`MAX_LIMIT`], and [`DecisionError::AvailableExceedsCapacity`]
    /// when `available` exceeds `capacity`.
    pub const fn try_new(
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
            capacity,
            available,
            replenishes_after,
        })
    }

    /// Returns the maximum immediately available policy allowance.
    pub const fn capacity(self) -> u64 {
        self.capacity
    }

    /// Returns the allowance available after consuming this check.
    pub const fn available(self) -> u64 {
        self.available
    }

    /// Returns the time until the policy's full capacity is next available.
    pub const fn replenishes_after(self) -> Duration {
        self.replenishes_after
    }
}

/// A read-only, discriminated view of an [`Admitted`] decision.
///
/// Both variants permit the request. Only a quota denial can be shadowed, so
/// the shadow variant carries a [`QuotaDenial`] rather than a [`DenialView`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmittedView {
    /// Quota was consumed.
    Allowed {
        /// Validated allowance metadata.
        allowance: Allowance,
    },
    /// Quota was exceeded in shadow mode and nothing was consumed.
    ShadowDenied {
        /// Validated quota-exhaustion details.
        denial: QuotaDenial,
    },
}

/// A decision that permits the request.
///
/// Every admitted decision is either a consumed [`Allowance`] or a quota
/// denial observed under a shadow policy. An enforced denial is not
/// representable, so code that receives an `Admitted` value, such as a
/// request handler behind admission middleware, never re-checks enforcement.
/// [`Decision::admit`] produces one from a backend decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admitted {
    outcome: AdmittedOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmittedOutcome {
    Allowed(Allowance),
    ShadowDenied(QuotaDenial),
}

impl Admitted {
    /// Constructs an admitted decision from a consumed allowance.
    pub const fn allowed(allowance: Allowance) -> Self {
        Self {
            outcome: AdmittedOutcome::Allowed(allowance),
        }
    }

    /// Constructs an admitted shadow quota denial.
    pub const fn shadow_denied(denial: QuotaDenial) -> Self {
        Self {
            outcome: AdmittedOutcome::ShadowDenied(denial),
        }
    }

    /// Returns a read-only view that discriminates every admitted outcome.
    pub const fn view(&self) -> AdmittedView {
        match self.outcome {
            AdmittedOutcome::Allowed(allowance) => AdmittedView::Allowed { allowance },
            AdmittedOutcome::ShadowDenied(denial) => AdmittedView::ShadowDenied { denial },
        }
    }
}

impl From<Allowance> for Admitted {
    fn from(allowance: Allowance) -> Self {
        Self::allowed(allowance)
    }
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
        /// Validated allowance metadata.
        allowance: Allowance,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Admitted(Admitted),
    Denied(Denial),
}

/// The outcome of evaluating one check.
///
/// Allowed outcomes carry an [`Allowance`] describing the quota available
/// after the check and the backend-reported time until full capacity is
/// replenished. Denied outcomes carry a [`Denial`]. Shadow-denied outcomes
/// carry a [`QuotaDenial`] and permit the request without consuming quota.
///
/// [`Decision::permits_request`] is the only boolean admission predicate.
/// [`Decision::admit`] splits a decision into the [`Admitted`] outcome the
/// application may proceed with or the [`Denial`] it must enforce, and
/// [`Decision::view`] names every outcome for telemetry.
///
/// With the `serde` feature, this is an object tagged by `outcome`. Invalid
/// allowed metadata, such as `available` exceeding `capacity`, is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    outcome: Outcome,
}

impl Decision {
    /// Constructs an allowed decision from a consumed allowance.
    pub const fn allowed(allowance: Allowance) -> Self {
        Self {
            outcome: Outcome::Admitted(Admitted::allowed(allowance)),
        }
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
            outcome: Outcome::Admitted(Admitted::shadow_denied(denial)),
        }
    }

    /// Returns a read-only view that discriminates every valid outcome.
    pub const fn view(&self) -> DecisionView {
        match self.outcome {
            Outcome::Admitted(admitted) => match admitted.view() {
                AdmittedView::Allowed { allowance } => DecisionView::Allowed { allowance },
                AdmittedView::ShadowDenied { denial } => DecisionView::ShadowDenied { denial },
            },
            Outcome::Denied(denial) => DecisionView::Denied {
                denial: denial.view(),
            },
        }
    }

    /// Returns whether the application may proceed.
    ///
    /// This is the only boolean admission predicate. It is true for consumed
    /// allowances and for quota denials from a shadow policy, and false for
    /// every enforced denial. Use [`Decision::admit`] to also obtain the
    /// admitted outcome or the denial to enforce, and [`Decision::view`] for
    /// telemetry that distinguishes shadow denials from allowances.
    pub const fn permits_request(&self) -> bool {
        matches!(self.outcome, Outcome::Admitted(_))
    }

    /// Splits the decision into the admitted outcome or the denial to enforce.
    ///
    /// The split is lossless: `Ok` holds the allowed or shadow-denied outcome
    /// the application may proceed with, and `Err` holds the enforced denial
    /// it must reject. `Ok` is returned exactly when
    /// [`Decision::permits_request`] is true.
    ///
    /// # Errors
    ///
    /// Returns the enforced [`Denial`] when the application must reject the
    /// request.
    pub const fn admit(self) -> Result<Admitted, Denial> {
        match self.outcome {
            Outcome::Admitted(admitted) => Ok(admitted),
            Outcome::Denied(denial) => Err(denial),
        }
    }
}

impl From<Allowance> for Decision {
    fn from(allowance: Allowance) -> Self {
        Self::allowed(allowance)
    }
}

impl From<Admitted> for Decision {
    fn from(admitted: Admitted) -> Self {
        Self {
            outcome: Outcome::Admitted(admitted),
        }
    }
}

/// The atomic outcome of evaluating checks in caller-supplied order.
///
/// An allowed batch contains one [`Allowance`] for each input check, in the
/// same order; a denied member is not representable. A denied batch reports
/// the original input index that failed together with the size of the batch
/// it was evaluated for; the index is validated below that size when the
/// batch is constructed, so a denied batch always describes at least one
/// check. Backends must not consume any check when returning an enforced
/// denial.
///
/// With the `serde` feature, this is an object tagged by `outcome`. Allowed
/// objects carry `allowances`. Denied objects carry `index` and `batch_size`,
/// and an index at or beyond the batch size is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchDecision {
    outcome: BatchOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BatchOutcome {
    Allowed(Vec<Allowance>),
    Denied {
        index: usize,
        batch_size: NonZeroUsize,
        denial: Denial,
    },
    ShadowDenied {
        index: usize,
        batch_size: NonZeroUsize,
        denial: QuotaDenial,
    },
}

/// A read-only, discriminated view of a [`BatchDecision`].
///
/// Allowances remain in caller order. Denial indices always refer to the
/// original caller-supplied input order and are always below the reported
/// batch size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchDecisionView<'a> {
    /// Every check was allowed and consumed atomically.
    Allowed {
        /// One allowance per input check, in caller order.
        allowances: &'a [Allowance],
    },
    /// The application must enforce the named input's denial.
    Denied {
        /// Index of the denied input in caller order.
        index: usize,
        /// Number of checks in the evaluated batch; `index` is below it.
        batch_size: NonZeroUsize,
        /// Backend-reported denial reason and details.
        denial: DenialView,
    },
    /// The named input exceeded quota in shadow mode.
    ShadowDenied {
        /// Index of the shadow-denied input in caller order.
        index: usize,
        /// Number of checks in the evaluated batch; `index` is below it.
        batch_size: NonZeroUsize,
        /// Validated quota-exhaustion details.
        denial: QuotaDenial,
    },
}

/// Validates a denied input index against its batch size.
const fn validate_batch_index(
    index: usize,
    batch_size: usize,
) -> Result<NonZeroUsize, DecisionError> {
    match NonZeroUsize::new(batch_size) {
        Some(batch_size) if index < batch_size.get() => Ok(batch_size),
        _ => Err(DecisionError::DeniedIndexOutOfRange { index, batch_size }),
    }
}

impl BatchDecision {
    /// Constructs an allowed batch from consumed allowances in caller order.
    pub fn allowed(allowances: Vec<Allowance>) -> Self {
        Self {
            outcome: BatchOutcome::Allowed(allowances),
        }
    }

    /// Constructs an enforced batch denial, panicking if the index is out of
    /// range.
    ///
    /// Backend implementations that cannot prove `index` is below
    /// `batch_size` should use [`BatchDecision::try_denied`] instead.
    ///
    /// # Panics
    ///
    /// Panics when `index` is not below `batch_size`.
    pub fn denied(index: usize, batch_size: usize, denial: impl Into<Denial>) -> Self {
        Self::try_denied(index, batch_size, denial)
            .expect("denied batch index must be below the batch size")
    }

    /// Constructs an enforced batch denial.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionError::DeniedIndexOutOfRange`] when `index` is not
    /// below `batch_size`, which also rejects an empty batch.
    pub fn try_denied(
        index: usize,
        batch_size: usize,
        denial: impl Into<Denial>,
    ) -> Result<Self, DecisionError> {
        let batch_size = validate_batch_index(index, batch_size)?;
        Ok(Self {
            outcome: BatchOutcome::Denied {
                index,
                batch_size,
                denial: denial.into(),
            },
        })
    }

    /// Constructs a shadow batch denial, panicking if the index is out of
    /// range.
    ///
    /// # Panics
    ///
    /// Panics when `index` is not below `batch_size`.
    pub const fn shadow_denied(index: usize, batch_size: usize, denial: QuotaDenial) -> Self {
        let Ok(batch_size) = validate_batch_index(index, batch_size) else {
            panic!("shadow-denied batch index must be below the batch size")
        };
        Self {
            outcome: BatchOutcome::ShadowDenied {
                index,
                batch_size,
                denial,
            },
        }
    }

    /// Constructs a shadow batch denial.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionError::DeniedIndexOutOfRange`] when `index` is not
    /// below `batch_size`, which also rejects an empty batch.
    pub const fn try_shadow_denied(
        index: usize,
        batch_size: usize,
        denial: QuotaDenial,
    ) -> Result<Self, DecisionError> {
        let batch_size = match validate_batch_index(index, batch_size) {
            Ok(batch_size) => batch_size,
            Err(error) => return Err(error),
        };
        Ok(Self {
            outcome: BatchOutcome::ShadowDenied {
                index,
                batch_size,
                denial,
            },
        })
    }

    /// Returns a read-only view that discriminates every valid outcome.
    pub fn view(&self) -> BatchDecisionView<'_> {
        match &self.outcome {
            BatchOutcome::Allowed(allowances) => BatchDecisionView::Allowed { allowances },
            BatchOutcome::Denied {
                index,
                batch_size,
                denial,
            } => BatchDecisionView::Denied {
                index: *index,
                batch_size: *batch_size,
                denial: denial.view(),
            },
            BatchOutcome::ShadowDenied {
                index,
                batch_size,
                denial,
            } => BatchDecisionView::ShadowDenied {
                index: *index,
                batch_size: *batch_size,
                denial: *denial,
            },
        }
    }

    /// Returns whether the application may proceed.
    ///
    /// This is the only boolean admission predicate. It is true for allowed
    /// and shadow-denied batches and false for every enforced denial. Match
    /// [`BatchDecision::view`] for anything else.
    pub const fn permits_request(&self) -> bool {
        !matches!(self.outcome, BatchOutcome::Denied { .. })
    }

    /// Consumes an allowed batch and returns its allowances in caller order.
    ///
    /// # Errors
    ///
    /// Returns the unchanged batch when it is an enforced or shadow denial.
    pub fn try_into_allowed(self) -> Result<Vec<Allowance>, Self> {
        match self.outcome {
            BatchOutcome::Allowed(allowances) => Ok(allowances),
            BatchOutcome::Denied { .. } | BatchOutcome::ShadowDenied { .. } => Err(self),
        }
    }

    /// Converts a batch-of-one outcome into its single-check decision.
    ///
    /// Returns the original batch when it was not evaluated for exactly one
    /// check: an allowed result with any other number of allowances, or a
    /// denial whose batch size is not one.
    ///
    /// # Errors
    ///
    /// Returns the unchanged batch when it is not a batch-of-one result.
    pub fn try_into_single_decision(self) -> Result<Decision, Self> {
        match self.outcome {
            BatchOutcome::Allowed(allowances) => match allowances.as_slice() {
                [allowance] => Ok(Decision::allowed(*allowance)),
                _ => Err(Self {
                    outcome: BatchOutcome::Allowed(allowances),
                }),
            },
            BatchOutcome::Denied {
                batch_size, denial, ..
            } if batch_size.get() == 1 => Ok(Decision::denied(denial)),
            BatchOutcome::ShadowDenied {
                batch_size, denial, ..
            } if batch_size.get() == 1 => Ok(Decision::shadow_denied(denial)),
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
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AllowanceWire {
    capacity: u64,
    available: u64,
    replenishes_after: Duration,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Allowance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = AllowanceWire {
            capacity: self.capacity,
            available: self.available,
            replenishes_after: self.replenishes_after,
        };
        serde::Serialize::serialize(&wire, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Allowance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = <AllowanceWire as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(wire.capacity, wire.available, wire.replenishes_after)
            .map_err(serde::de::Error::custom)
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
            Outcome::Admitted(admitted) => match admitted.view() {
                AdmittedView::Allowed { allowance } => DecisionRef::Allowed {
                    capacity: allowance.capacity(),
                    available: allowance.available(),
                    replenishes_after: allowance.replenishes_after(),
                },
                AdmittedView::ShadowDenied { denial } => DecisionRef::ShadowDenied {
                    denial: Denial::quota_exceeded(denial),
                },
            },
            Outcome::Denied(denial) => DecisionRef::Denied { denial },
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
            } => Allowance::try_new(capacity, available, replenishes_after)
                .map(Self::allowed)
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
    Allowed {
        allowances: &'a [Allowance],
    },
    Denied {
        index: usize,
        batch_size: NonZeroUsize,
        denial: &'a Denial,
    },
    ShadowDenied {
        index: usize,
        batch_size: NonZeroUsize,
        denial: Denial,
    },
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum BatchDecisionWire {
    Allowed {
        allowances: Vec<Allowance>,
    },
    Denied {
        index: usize,
        batch_size: usize,
        denial: Denial,
    },
    ShadowDenied {
        index: usize,
        batch_size: usize,
        denial: Denial,
    },
}

#[cfg(feature = "serde")]
impl serde::Serialize for BatchDecision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = match &self.outcome {
            BatchOutcome::Allowed(allowances) => BatchDecisionRef::Allowed { allowances },
            BatchOutcome::Denied {
                index,
                batch_size,
                denial,
            } => BatchDecisionRef::Denied {
                index: *index,
                batch_size: *batch_size,
                denial,
            },
            BatchOutcome::ShadowDenied {
                index,
                batch_size,
                denial,
            } => BatchDecisionRef::ShadowDenied {
                index: *index,
                batch_size: *batch_size,
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
            BatchDecisionWire::Allowed { allowances } => Ok(Self::allowed(allowances)),
            BatchDecisionWire::Denied {
                index,
                batch_size,
                denial,
            } => Self::try_denied(index, batch_size, denial).map_err(serde::de::Error::custom),
            BatchDecisionWire::ShadowDenied {
                index,
                batch_size,
                denial,
            } => match denial.view() {
                DenialView::QuotaExceeded(denial) => {
                    Self::try_shadow_denied(index, batch_size, denial)
                        .map_err(serde::de::Error::custom)
                }
                DenialView::StorageCapacity { .. } => Err(serde::de::Error::custom(
                    "only quota exhaustion can be shadowed",
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use super::{
        Admitted, AdmittedView, Allowance, BatchDecision, BatchDecisionView, Decision,
        DecisionError, DecisionView, Denial, DenialView, QuotaDenial, RetryAfter,
    };

    fn allowance(capacity: u64, available: u64, replenishes_after: Duration) -> Allowance {
        Allowance::try_new(capacity, available, replenishes_after).unwrap()
    }

    fn quota(capacity: u64, retry_after: Duration) -> QuotaDenial {
        QuotaDenial::try_new(capacity, retry_after).unwrap()
    }

    #[test]
    fn allowed_decision_exposes_its_allowance() {
        let allowance = allowance(8, 7, Duration::from_millis(59_999));
        let decision = Decision::allowed(allowance);

        assert!(decision.permits_request());
        assert_eq!(decision, Decision::from(allowance));
        assert_eq!(decision.view(), DecisionView::Allowed { allowance });
        assert_eq!(allowance.capacity(), 8);
        assert_eq!(allowance.available(), 7);
        assert_eq!(allowance.replenishes_after(), Duration::from_millis(59_999));
    }

    #[test]
    fn quota_denial_exposes_exact_and_ceiling_retry_duration() {
        let quota = quota(8, Duration::from_millis(1_001));
        let decision = Decision::denied(quota);

        assert!(!decision.permits_request());
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
    fn admit_splits_every_outcome_consistently_with_the_predicate() {
        let allowance = allowance(8, 7, Duration::from_mins(1));
        let quota = quota(8, Duration::from_secs(30));
        let capacity = Denial::storage_capacity(None);

        for (decision, expected) in [
            (
                Decision::allowed(allowance),
                Ok(Admitted::allowed(allowance)),
            ),
            (
                Decision::shadow_denied(quota),
                Ok(Admitted::shadow_denied(quota)),
            ),
            (Decision::denied(quota), Err(Denial::quota_exceeded(quota))),
            (Decision::denied(capacity), Err(capacity)),
        ] {
            assert_eq!(decision.admit(), expected);
            assert_eq!(decision.permits_request(), expected.is_ok());
            if let Ok(admitted) = expected {
                assert_eq!(Decision::from(admitted), decision);
            }
        }
    }

    #[test]
    fn admitted_views_discriminate_allowances_from_shadow_denials() {
        let allowance = allowance(8, 7, Duration::from_mins(1));
        let quota = quota(8, Duration::from_secs(30));

        assert_eq!(
            Admitted::allowed(allowance).view(),
            AdmittedView::Allowed { allowance }
        );
        assert_eq!(Admitted::from(allowance), Admitted::allowed(allowance));
        assert_eq!(
            Admitted::shadow_denied(quota).view(),
            AdmittedView::ShadowDenied { denial: quota }
        );
    }

    #[test]
    fn batch_of_one_converts_to_a_single_decision() {
        let allowance = allowance(8, 7, Duration::from_mins(1));
        let denied = quota(8, Duration::from_mins(1));

        assert_eq!(
            BatchDecision::allowed(vec![allowance]).try_into_single_decision(),
            Ok(Decision::allowed(allowance))
        );
        assert_eq!(
            BatchDecision::denied(0, 1, denied).try_into_single_decision(),
            Ok(Decision::denied(denied))
        );
    }

    #[test]
    fn malformed_batch_of_one_is_rejected() {
        let allowance = allowance(8, 7, Duration::from_mins(1));
        let denial = quota(8, Duration::from_mins(1));

        assert_eq!(
            BatchDecision::allowed(Vec::new()).try_into_single_decision(),
            Err(BatchDecision::allowed(Vec::new()))
        );
        assert_eq!(
            BatchDecision::allowed(vec![allowance, allowance]).try_into_single_decision(),
            Err(BatchDecision::allowed(vec![allowance, allowance]))
        );
        assert!(
            BatchDecision::denied(1, 2, denial)
                .try_into_single_decision()
                .is_err()
        );
        assert!(
            BatchDecision::denied(0, 2, denial)
                .try_into_single_decision()
                .is_err()
        );
    }

    #[test]
    fn batch_denial_index_must_be_below_the_batch_size() {
        let denial = quota(8, Duration::from_mins(1));

        assert_eq!(
            BatchDecision::try_denied(1, 1, denial),
            Err(DecisionError::DeniedIndexOutOfRange {
                index: 1,
                batch_size: 1,
            })
        );
        assert_eq!(
            BatchDecision::try_denied(0, 0, denial),
            Err(DecisionError::DeniedIndexOutOfRange {
                index: 0,
                batch_size: 0,
            })
        );
        assert_eq!(
            BatchDecision::try_shadow_denied(3, 2, denial),
            Err(DecisionError::DeniedIndexOutOfRange {
                index: 3,
                batch_size: 2,
            })
        );
        assert_eq!(
            BatchDecision::try_denied(1, 2, denial),
            Ok(BatchDecision::denied(1, 2, denial))
        );
        assert_eq!(
            BatchDecision::try_shadow_denied(1, 2, denial),
            Ok(BatchDecision::shadow_denied(1, 2, denial))
        );
    }

    #[test]
    fn allowed_batches_yield_their_allowances_in_caller_order() {
        let first = allowance(8, 7, Duration::from_mins(1));
        let second = allowance(4, 2, Duration::from_secs(30));
        let shadow = BatchDecision::shadow_denied(0, 2, quota(8, Duration::from_secs(30)));

        assert_eq!(
            BatchDecision::allowed(vec![first, second]).try_into_allowed(),
            Ok(vec![first, second])
        );
        assert_eq!(shadow.clone().try_into_allowed(), Err(shadow));
    }

    #[test]
    fn shadow_denial_permits_the_request_without_claiming_consumption() {
        let denial = quota(8, Duration::from_millis(30_001));
        let decision = Decision::shadow_denied(denial);

        assert!(decision.permits_request());
        assert_eq!(decision.view(), DecisionView::ShadowDenied { denial });
        assert_eq!(denial.retry_after().seconds(), 31);
        assert_eq!(
            BatchDecision::shadow_denied(0, 1, denial).try_into_single_decision(),
            Ok(decision)
        );
        assert!(BatchDecision::shadow_denied(0, 1, denial).permits_request());
        assert!(!BatchDecision::denied(0, 1, denial).permits_request());
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
        let first = allowance(8, 7, Duration::from_mins(1));
        let second = allowance(4, 2, Duration::from_secs(30));
        let allowed_batch = BatchDecision::allowed(vec![first, second]);
        assert_eq!(
            allowed_batch.view(),
            BatchDecisionView::Allowed {
                allowances: &[first, second],
            }
        );

        let quota = quota(8, Duration::from_secs(30));
        let denied = BatchDecision::denied(1, 2, quota);
        assert_eq!(
            denied.view(),
            BatchDecisionView::Denied {
                index: 1,
                batch_size: NonZeroUsize::new(2).unwrap(),
                denial: DenialView::QuotaExceeded(quota),
            }
        );

        let capacity = BatchDecision::denied(2, 3, Denial::storage_capacity(None));
        assert_eq!(
            capacity.view(),
            BatchDecisionView::Denied {
                index: 2,
                batch_size: NonZeroUsize::new(3).unwrap(),
                denial: DenialView::StorageCapacity { retry_after: None },
            }
        );

        let shadow = BatchDecision::shadow_denied(2, 3, quota);
        assert_eq!(
            shadow.view(),
            BatchDecisionView::ShadowDenied {
                index: 2,
                batch_size: NonZeroUsize::new(3).unwrap(),
                denial: quota,
            }
        );
        assert_eq!(shadow.clone().try_into_single_decision(), Err(shadow));
    }

    #[test]
    fn invalid_metadata_is_rejected_at_construction() {
        assert_eq!(
            QuotaDenial::try_new(0, Duration::ZERO),
            Err(DecisionError::InvalidCapacity { capacity: 0 })
        );
        assert_eq!(
            Allowance::try_new(0, 0, Duration::ZERO),
            Err(DecisionError::InvalidCapacity { capacity: 0 })
        );
        assert_eq!(
            Allowance::try_new(8, 9, Duration::ZERO),
            Err(DecisionError::AvailableExceedsCapacity {
                capacity: 8,
                available: 9,
            })
        );
    }
}
