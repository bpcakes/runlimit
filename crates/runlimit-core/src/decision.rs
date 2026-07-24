use std::time::Duration;

/// Structured details for a denied check.
///
/// A quota denial always contains its policy limit and the remaining window
/// measured by the backend. A storage-capacity denial may contain the duration
/// until the backend's earliest known expiry, when one is available.
///
/// Process-local backends can measure the duration at evaluation time exactly.
/// Distributed backends may return a safe upper bound measured with their
/// authoritative clock, which can overstate the duration at the caller by
/// commit and transport time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Denial {
    /// Consuming the requested cost would exceed the configured quota.
    QuotaExceeded {
        /// Configured policy limit.
        limit: u64,
        /// Remaining duration of the active window.
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
    limit: u64,
    remaining: u64,
    reset_after: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Allowed(Allowance),
    Denied(Denial),
}

/// The outcome of evaluating one check.
///
/// Allowed outcomes report quota remaining after the check and the
/// backend-reported time until the anchored window resets. Denied outcomes
/// carry a [`Denial`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    outcome: Outcome,
}

impl Decision {
    /// Constructs an allowed decision.
    ///
    /// Storage backends should pass the remaining quota after consuming the
    /// check's cost. This low-level constructor trusts the backend to ensure
    /// `remaining <= limit`.
    pub const fn allowed(limit: u64, remaining: u64, reset_after: Duration) -> Self {
        Self {
            outcome: Outcome::Allowed(Allowance {
                limit,
                remaining,
                reset_after,
            }),
        }
    }

    /// Constructs a denied decision.
    pub const fn denied(denial: Denial) -> Self {
        Self {
            outcome: Outcome::Denied(denial),
        }
    }

    /// Returns whether the check was allowed.
    pub const fn is_allowed(&self) -> bool {
        matches!(self.outcome, Outcome::Allowed(_))
    }

    /// Returns whether the check was denied.
    pub const fn is_denied(&self) -> bool {
        !self.is_allowed()
    }

    /// Returns the configured limit when it is meaningful for this outcome.
    ///
    /// Allowed decisions and quota denials have a limit. Storage-capacity
    /// denials do not.
    pub const fn limit(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Allowed(allowance) => Some(allowance.limit),
            Outcome::Denied(Denial::QuotaExceeded { limit, .. }) => Some(limit),
            Outcome::Denied(Denial::StorageCapacity { .. }) => None,
        }
    }

    /// Returns the quota remaining after an allowed check.
    pub const fn remaining(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Allowed(allowance) => Some(allowance.remaining),
            Outcome::Denied(_) => None,
        }
    }

    /// Returns the backend-reported time until an allowed check's anchored
    /// window resets.
    pub const fn reset_after(&self) -> Option<Duration> {
        match self.outcome {
            Outcome::Allowed(allowance) => Some(allowance.reset_after),
            Outcome::Denied(_) => None,
        }
    }

    /// Returns the backend-reported duration after which a denied check may
    /// retry.
    pub const fn retry_after(&self) -> Option<Duration> {
        match self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) => denial.retry_after(),
        }
    }

    /// Returns a whole-second `Retry-After` value rounded up, if known.
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) => denial.retry_after_seconds(),
        }
    }

    /// Returns denial details for a denied check.
    pub const fn denial(&self) -> Option<&Denial> {
        match &self.outcome {
            Outcome::Allowed(_) => None,
            Outcome::Denied(denial) => Some(denial),
        }
    }
}

/// The atomic outcome of evaluating checks in caller-supplied order.
///
/// An allowed batch contains one allowed decision for each input check, in the
/// same order. A denied batch reports the original input index that failed.
/// Backends must not consume any check when returning [`BatchDecision::Denied`].
#[derive(Clone, Debug, Eq, PartialEq)]
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
}

impl BatchDecision {
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
            Self::Allowed(decisions) if matches!(decisions.as_slice(), [decision] if decision.is_allowed()) => {
                Ok(decisions[0])
            }
            Self::Denied { index: 0, denial } => Ok(Decision::denied(denial)),
            batch => Err(batch),
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

    use super::{BatchDecision, Decision, Denial};

    #[test]
    fn allowed_decision_exposes_remaining_and_reset() {
        let decision = Decision::allowed(8, 7, Duration::from_millis(59_999));

        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert_eq!(decision.limit(), Some(8));
        assert_eq!(decision.remaining(), Some(7));
        assert_eq!(decision.reset_after(), Some(Duration::from_millis(59_999)));
        assert_eq!(decision.retry_after(), None);
        assert_eq!(decision.denial(), None);
    }

    #[test]
    fn quota_denial_exposes_exact_and_ceiling_retry_duration() {
        let denial = Denial::QuotaExceeded {
            limit: 8,
            retry_after: Duration::from_millis(1_001),
        };
        let decision = Decision::denied(denial);

        assert!(decision.is_denied());
        assert_eq!(decision.limit(), Some(8));
        assert_eq!(decision.remaining(), None);
        assert_eq!(decision.reset_after(), None);
        assert_eq!(decision.retry_after(), Some(Duration::from_millis(1_001)));
        assert_eq!(decision.retry_after_seconds(), Some(2));
        assert_eq!(decision.denial(), Some(&denial));
        assert!(matches!(
            denial,
            Denial::QuotaExceeded {
                limit: 8,
                retry_after
            } if retry_after == Duration::from_millis(1_001)
        ));
    }

    #[test]
    fn retry_after_seconds_preserves_exact_seconds() {
        let denial = Denial::QuotaExceeded {
            limit: 1,
            retry_after: Duration::from_secs(3),
        };

        assert_eq!(denial.retry_after_seconds(), Some(3));
    }

    #[test]
    fn retry_after_seconds_saturates_without_losing_exact_duration() {
        let duration = Duration::new(u64::MAX, 1);
        let denial = Denial::QuotaExceeded {
            limit: 1,
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
        assert_eq!(decision.limit(), None);
        assert_eq!(decision.retry_after(), None);
    }

    #[test]
    fn batch_of_one_converts_to_a_single_decision() {
        let allowed = Decision::allowed(8, 7, Duration::from_secs(60));
        let denied = Denial::QuotaExceeded {
            limit: 8,
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
            limit: 8,
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
}
