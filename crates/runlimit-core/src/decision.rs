use std::time::Duration;

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
#[non_exhaustive]
pub enum Denial {
    /// Consuming the requested cost would exceed the configured quota.
    QuotaExceeded {
        /// Maximum immediately available policy allowance.
        capacity: u64,
        /// Duration until the rejected cost can be retried.
        retry_after: Duration,
    },
    /// A bounded backend could not safely allocate storage for a new key.
    StorageCapacity {
        /// Duration until capacity may become available, when known.
        retry_after: Option<Duration>,
    },
}

impl Denial {
    /// Returns the backend-reported duration after which the caller may retry,
    /// if known.
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::QuotaExceeded { retry_after, .. } => Some(*retry_after),
            Self::StorageCapacity { retry_after } => *retry_after,
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
    /// Constructs an allowed decision.
    ///
    /// Storage backends should pass the available allowance after consuming
    /// the check's cost. This low-level constructor trusts the backend to
    /// ensure `available <= capacity`.
    pub const fn allowed(capacity: u64, available: u64, replenishes_after: Duration) -> Self {
        Self {
            outcome: Outcome::Allowed(Allowance {
                capacity,
                available,
                replenishes_after,
            }),
        }
    }

    /// Constructs a denied decision.
    pub const fn denied(denial: Denial) -> Self {
        Self {
            outcome: Outcome::Denied(denial),
        }
    }

    /// Constructs a shadow quota denial.
    ///
    /// Backends must use this only for [`Denial::QuotaExceeded`]. Storage
    /// capacity remains an enforced denial in every quota mode.
    pub const fn shadow_denied(denial: Denial) -> Self {
        Self {
            outcome: Outcome::ShadowDenied(denial),
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
            Outcome::Denied(Denial::QuotaExceeded { capacity, .. })
            | Outcome::ShadowDenied(Denial::QuotaExceeded { capacity, .. }) => Some(capacity),
            Outcome::Denied(Denial::StorageCapacity { .. })
            | Outcome::ShadowDenied(Denial::StorageCapacity { .. }) => None,
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

    const fn was_consumed(&self) -> bool {
        matches!(self.outcome, Outcome::Allowed(_))
    }
}

/// The atomic outcome of evaluating checks in caller-supplied order.
///
/// An allowed batch contains one allowed decision for each input check, in the
/// same order. A denied batch reports the original input index that failed.
/// Backends must not consume any check when returning [`BatchDecision::Denied`].
///
/// With the `serde` feature, this is an object tagged by `outcome`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BatchDecision {
    /// Every input check was allowed.
    Allowed(Vec<Decision>),
    /// One input check caused the whole batch to be denied.
    Denied {
        /// Index in the caller's original input sequence.
        index: usize,
        /// Details of the denial.
        denial: Denial,
    },
    /// Quota was exceeded for one shadow policy, so nothing was consumed but
    /// the application may proceed.
    ShadowDenied {
        /// Index in the caller's original input sequence.
        index: usize,
        /// Quota-denial details.
        denial: Denial,
    },
}

impl BatchDecision {
    /// Returns whether the application may proceed.
    pub const fn permits_request(&self) -> bool {
        !matches!(self, Self::Denied { .. })
    }

    /// Returns whether evaluation encountered quota or capacity denial.
    pub const fn would_deny(&self) -> bool {
        !matches!(self, Self::Allowed(_))
    }

    /// Returns whether the application must reject the operation.
    pub const fn is_enforced_denial(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Returns whether quota was exceeded in shadow mode.
    pub const fn is_shadow_denied(&self) -> bool {
        matches!(self, Self::ShadowDenied { .. })
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
        match self {
            Self::Allowed(decisions) if matches!(decisions.as_slice(), [decision] if decision.was_consumed()) => {
                Ok(decisions[0])
            }
            Self::Denied { index: 0, denial } => Ok(Decision::denied(denial)),
            Self::ShadowDenied { index: 0, denial } => Ok(Decision::shadow_denied(denial)),
            batch => Err(batch),
        }
    }
}

#[cfg(feature = "serde")]
fn validate_denial(denial: &Denial) -> Result<(), &'static str> {
    match denial {
        Denial::QuotaExceeded { capacity, .. } => {
            if *capacity == 0 {
                return Err("a quota denial capacity must be greater than zero");
            }
            if *capacity > crate::MAX_LIMIT {
                return Err("a quota denial capacity exceeds the portable maximum");
            }
        }
        Denial::StorageCapacity { .. } => {}
    }
    Ok(())
}

#[cfg(feature = "serde")]
fn validate_decision(decision: &Decision) -> Result<(), &'static str> {
    match decision.outcome {
        Outcome::Allowed(allowance) => {
            if allowance.capacity == 0 {
                return Err("an allowed decision capacity must be greater than zero");
            }
            if allowance.capacity > crate::MAX_LIMIT {
                return Err("an allowed decision capacity exceeds the portable maximum");
            }
            if allowance.available > allowance.capacity {
                return Err("allowed decision available quota exceeds its capacity");
            }
            Ok(())
        }
        Outcome::Denied(denial) => validate_denial(&denial),
        Outcome::ShadowDenied(denial) => {
            if !matches!(denial, Denial::QuotaExceeded { .. }) {
                return Err("only quota exhaustion can be shadowed");
            }
            validate_denial(&denial)
        }
    }
}

#[cfg(feature = "serde")]
fn validate_batch_decision(batch: &BatchDecision) -> Result<(), &'static str> {
    match batch {
        BatchDecision::Allowed(decisions) => {
            if decisions.iter().any(|decision| !decision.was_consumed()) {
                return Err("an allowed batch can contain only consumed allowed decisions");
            }
            for decision in decisions {
                validate_decision(decision)?;
            }
            Ok(())
        }
        BatchDecision::Denied { denial, .. } => validate_denial(denial),
        BatchDecision::ShadowDenied { denial, .. } => {
            if !matches!(denial, Denial::QuotaExceeded { .. }) {
                return Err("only quota exhaustion can be shadowed");
            }
            validate_denial(denial)
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
        validate_denial(self).map_err(<S::Error as serde::ser::Error>::custom)?;
        let wire = match *self {
            Self::QuotaExceeded {
                capacity,
                retry_after,
            } => DenialRef::QuotaExceeded {
                capacity,
                retry_after,
            },
            Self::StorageCapacity { retry_after } => DenialRef::StorageCapacity { retry_after },
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
        let denial = match wire {
            DenialWire::QuotaExceeded {
                capacity,
                retry_after,
            } => Self::QuotaExceeded {
                capacity,
                retry_after,
            },
            DenialWire::StorageCapacity { retry_after } => Self::StorageCapacity { retry_after },
        };
        validate_denial(&denial).map_err(serde::de::Error::custom)?;
        Ok(denial)
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
        validate_decision(self).map_err(<S::Error as serde::ser::Error>::custom)?;
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
        let decision = match wire {
            DecisionWire::Allowed {
                capacity,
                available,
                replenishes_after,
            } => Self::allowed(capacity, available, replenishes_after),
            DecisionWire::Denied { denial } => Self::denied(denial),
            DecisionWire::ShadowDenied { denial } => Self::shadow_denied(denial),
        };
        validate_decision(&decision).map_err(serde::de::Error::custom)?;
        Ok(decision)
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
        validate_batch_decision(self).map_err(<S::Error as serde::ser::Error>::custom)?;
        let wire = match self {
            Self::Allowed(decisions) => BatchDecisionRef::Allowed { decisions },
            Self::Denied { index, denial } => BatchDecisionRef::Denied {
                index: *index,
                denial,
            },
            Self::ShadowDenied { index, denial } => BatchDecisionRef::ShadowDenied {
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
        let batch = match wire {
            BatchDecisionWire::Allowed { decisions } => Self::Allowed(decisions),
            BatchDecisionWire::Denied { index, denial } => Self::Denied { index, denial },
            BatchDecisionWire::ShadowDenied { index, denial } => {
                Self::ShadowDenied { index, denial }
            }
        };
        validate_batch_decision(&batch).map_err(serde::de::Error::custom)?;
        Ok(batch)
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

    use super::{BatchDecision, Decision, Denial};

    #[test]
    fn allowed_decision_exposes_available_and_replenishment() {
        let decision = Decision::allowed(8, 7, Duration::from_millis(59_999));

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
        let denial = Denial::QuotaExceeded {
            capacity: 8,
            retry_after: Duration::from_millis(1_001),
        };
        let decision = Decision::denied(denial);

        assert!(decision.is_denied());
        assert_eq!(decision.capacity(), Some(8));
        assert_eq!(decision.available(), None);
        assert_eq!(decision.replenishes_after(), None);
        assert_eq!(decision.retry_after(), Some(Duration::from_millis(1_001)));
        assert_eq!(decision.retry_after_seconds(), Some(2));
        assert_eq!(decision.denial(), Some(&denial));
        assert!(matches!(
            denial,
            Denial::QuotaExceeded {
                capacity: 8,
                retry_after
            } if retry_after == Duration::from_millis(1_001)
        ));
    }

    #[test]
    fn retry_after_seconds_preserves_exact_seconds() {
        let denial = Denial::QuotaExceeded {
            capacity: 1,
            retry_after: Duration::from_secs(3),
        };

        assert_eq!(denial.retry_after_seconds(), Some(3));
    }

    #[test]
    fn retry_after_seconds_saturates_without_losing_exact_duration() {
        let duration = Duration::new(u64::MAX, 1);
        let denial = Denial::QuotaExceeded {
            capacity: 1,
            retry_after: duration,
        };

        assert_eq!(denial.retry_after(), Some(duration));
        assert_eq!(denial.retry_after_seconds(), Some(u64::MAX));
    }

    #[test]
    fn storage_capacity_retry_can_be_unknown() {
        let denial = Denial::StorageCapacity { retry_after: None };
        let decision = Decision::denied(denial);

        assert!(matches!(
            denial,
            Denial::StorageCapacity { retry_after: None }
        ));
        assert_eq!(denial.retry_after(), None);
        assert_eq!(denial.retry_after_seconds(), None);
        assert_eq!(decision.capacity(), None);
        assert_eq!(decision.retry_after(), None);
    }

    #[test]
    fn batch_of_one_converts_to_a_single_decision() {
        let allowed = Decision::allowed(8, 7, Duration::from_secs(60));
        let denied = Denial::QuotaExceeded {
            capacity: 8,
            retry_after: Duration::from_secs(60),
        };

        assert_eq!(
            BatchDecision::Allowed(vec![allowed]).try_into_single_decision(),
            Ok(allowed)
        );
        assert_eq!(
            BatchDecision::Denied {
                index: 0,
                denial: denied
            }
            .try_into_single_decision(),
            Ok(Decision::denied(denied))
        );
    }

    #[test]
    fn malformed_batch_of_one_is_rejected() {
        let decision = Decision::allowed(8, 7, Duration::from_secs(60));
        let denial = Denial::QuotaExceeded {
            capacity: 8,
            retry_after: Duration::from_secs(60),
        };

        assert!(
            BatchDecision::Allowed(Vec::new())
                .try_into_single_decision()
                .is_err()
        );
        assert!(
            BatchDecision::Allowed(vec![decision, decision])
                .try_into_single_decision()
                .is_err()
        );
        assert!(
            BatchDecision::Allowed(vec![Decision::denied(denial)])
                .try_into_single_decision()
                .is_err()
        );
        assert!(
            BatchDecision::Denied { index: 1, denial }
                .try_into_single_decision()
                .is_err()
        );
    }

    #[test]
    fn shadow_denial_permits_the_request_without_claiming_consumption() {
        let denial = Denial::QuotaExceeded {
            capacity: 8,
            retry_after: Duration::from_secs(30),
        };
        let decision = Decision::shadow_denied(denial);

        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(decision.permits_request());
        assert!(decision.would_deny());
        assert!(decision.is_shadow_denied());
        assert_eq!(decision.available(), None);
        assert_eq!(decision.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(
            BatchDecision::ShadowDenied { index: 0, denial }.try_into_single_decision(),
            Ok(decision)
        );
    }
}
