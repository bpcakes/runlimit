use std::collections::{HashMap, hash_map::Entry};

use thiserror::Error;

use crate::{Check, QuotaMode, RateLimitPolicy};

/// Validates backend-independent structural requirements for an atomic batch.
///
/// Duplicate counters are reported in caller order: `duplicate_index` is the
/// earliest repeated input, and `first_index` is that counter's first input.
///
/// # Errors
///
/// Returns [`BatchError::BatchTooLarge`] before inspecting keys when the batch
/// exceeds `maximum`. Otherwise returns [`BatchError::DuplicateKey`] for the
/// first repeated logical counter.
pub fn validate_batch<P: RateLimitPolicy>(
    checks: &[Check<'_, P>],
    maximum: usize,
) -> Result<(), BatchError> {
    if checks.len() > maximum {
        return Err(BatchError::BatchTooLarge {
            actual: checks.len(),
            maximum,
        });
    }

    let first_mode = checks.first().map(|check| check.policy().quota_mode());
    let mut first_indices = HashMap::with_capacity(checks.len());
    for (duplicate_index, check) in checks.iter().enumerate() {
        if let Some(first) = first_mode
            && check.policy().quota_mode() != first
        {
            return Err(BatchError::MixedQuotaModes {
                first,
                index: duplicate_index,
                actual: check.policy().quota_mode(),
            });
        }
        match first_indices.entry(check.counter_key()) {
            Entry::Vacant(entry) => {
                entry.insert(duplicate_index);
            }
            Entry::Occupied(entry) => {
                return Err(BatchError::DuplicateKey {
                    first_index: *entry.get(),
                    duplicate_index,
                });
            }
        }
    }

    Ok(())
}

/// A backend-independent invalid atomic batch.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BatchError {
    /// The batch included the same logical counter more than once.
    #[error("batch check at index {duplicate_index} duplicates the counter at index {first_index}")]
    DuplicateKey {
        /// Index of the first occurrence in caller order.
        first_index: usize,
        /// Index of the repeated occurrence in caller order.
        duplicate_index: usize,
    },
    /// The batch contained more checks than the backend's configured maximum.
    #[error("batch has {actual} checks but the configured maximum is {maximum}")]
    BatchTooLarge {
        /// Submitted check count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The batch mixed enforced and shadow quota policies.
    #[error(
        "batch policy at index {index} uses quota mode {actual:?}, which differs from the first policy's {first:?} mode"
    )]
    MixedQuotaModes {
        /// Quota mode of the first input policy.
        first: QuotaMode,
        /// Index of the first input with a different mode.
        index: usize,
        /// Quota mode at `index`.
        actual: QuotaMode,
    },
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BatchError, validate_batch};
    use crate::{Check, FixedWindowPolicy, PolicyId, QuotaMode, ScopeId, SubjectKey};

    fn policy(id: &str) -> FixedWindowPolicy {
        FixedWindowPolicy::new(
            PolicyId::new(id).unwrap(),
            ScopeId::new("client").unwrap(),
            10,
            Duration::from_secs(60),
        )
        .unwrap()
    }

    fn subject(byte: u8) -> SubjectKey {
        SubjectKey::from_digest([byte; 32])
    }

    #[test]
    fn accepts_empty_and_distinct_batches() {
        let first_policy = policy("auth.alpha");
        let second_policy = policy("auth.beta");
        let checks = [
            Check::new(&first_policy, subject(1)),
            Check::new(&second_policy, subject(1)),
            Check::new(&first_policy, subject(2)),
        ];

        assert_eq!(validate_batch::<FixedWindowPolicy>(&[], 0), Ok(()));
        assert_eq!(validate_batch(&checks, checks.len()), Ok(()));
    }

    #[test]
    fn reports_the_first_duplicate_in_caller_order() {
        let alpha = policy("auth.alpha");
        let beta = policy("auth.beta");
        let checks = [
            Check::new(&beta, subject(1)),
            Check::new(&beta, subject(1)),
            Check::new(&alpha, subject(2)),
            Check::new(&alpha, subject(2)),
        ];

        assert_eq!(
            validate_batch(&checks, checks.len()),
            Err(BatchError::DuplicateKey {
                first_index: 0,
                duplicate_index: 1,
            })
        );
    }

    #[test]
    fn batch_size_error_takes_precedence_over_duplicate_detection() {
        let policy = policy("auth.alpha");
        let checks = [
            Check::new(&policy, subject(1)),
            Check::new(&policy, subject(1)),
        ];

        assert_eq!(
            validate_batch(&checks, 1),
            Err(BatchError::BatchTooLarge {
                actual: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn rejects_mixed_enforcement_modes_before_duplicate_detection() {
        let enforced = policy("auth.alpha");
        let shadow = policy("auth.beta").with_quota_mode(QuotaMode::Shadow);
        let checks = [
            Check::new(&enforced, subject(1)),
            Check::new(&shadow, subject(2)),
            Check::new(&enforced, subject(1)),
        ];

        assert_eq!(
            validate_batch(&checks, checks.len()),
            Err(BatchError::MixedQuotaModes {
                first: QuotaMode::Enforce,
                index: 1,
                actual: QuotaMode::Shadow,
            })
        );
    }
}
