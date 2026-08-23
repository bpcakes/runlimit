//! Response fields from `draft-ietf-httpapi-ratelimit-headers-11`.
//!
//! The draft defines `RateLimit-Policy` for stable quota policy metadata and
//! `RateLimit` for the service limit currently available to a client. Both are
//! HTTP Structured Field lists whose members identify policies with String
//! items.
//!
//! This module emits one list member at a time. Applications remain
//! responsible for selecting policies, combining multiple members when
//! appropriate, and deciding whether to attach the fields to a response.
//! Partition keys are intentionally unsupported so subject material cannot be
//! exposed accidentally.

use std::time::Duration;

use http::{HeaderName, HeaderValue};
use runlimit_core::{Decision, DecisionView, RateLimitPolicy};
use thiserror::Error;

/// Largest integer representable by an RFC 9651 Structured Field.
pub const MAX_STRUCTURED_FIELD_INTEGER: u64 = 999_999_999_999_999;

/// Maximum accepted byte length of a public policy name.
pub const MAX_POLICY_NAME_LENGTH: usize = 128;

/// A typed HTTP header name and value.
pub type HeaderField = (HeaderName, HeaderValue);

/// Encodes one `RateLimit-Policy` field.
///
/// The result has the form `"name";q=N;w=S`, where `q` is
/// [`RateLimitPolicy::quota`] and `w` is its exact whole-second
/// [`RateLimitPolicy::quota_period`]. The default quota unit from the draft is
/// requests; this helper therefore omits the optional `qu` parameter.
///
/// # Errors
///
/// Returns [`EncodingError`] when the public policy name is unsafe for an
/// HTTP Structured Field String, a numeric value exceeds the Structured Field
/// integer range, or the quota period is zero or not an exact whole number of
/// seconds.
pub fn quota_policy<P: RateLimitPolicy + ?Sized>(
    name: &str,
    policy: &P,
) -> Result<HeaderField, EncodingError> {
    let name = encode_policy_name(name)?;
    let quota = structured_integer(policy.quota())?;
    let period = policy.quota_period();
    if period.is_zero() {
        return Err(EncodingError::ZeroQuotaPeriod);
    }
    if period.subsec_nanos() != 0 {
        return Err(EncodingError::QuotaPeriodNotWholeSeconds { actual: period });
    }
    let period = structured_integer(period.as_secs())?;
    let value = header_value(format!("{name};q={quota};w={period}"))?;

    Ok((HeaderName::from_static("ratelimit-policy"), value))
}

/// Encodes one `RateLimit` field.
///
/// An allowed decision uses the immediately available allowance and rounds
/// its replenishment duration up to whole seconds. An enforced or shadow quota
/// denial uses `r=0` and rounds the backend's retry duration up in the same
/// way. Thus a shadow denial exposes the service value that would have applied
/// if the policy were enforced, without creating a `Retry-After` field or
/// choosing an HTTP status.
///
/// Storage-capacity denials cannot be represented as a quota service limit and
/// return [`EncodingError::UnsupportedDecision`].
///
/// # Errors
///
/// Returns [`EncodingError`] when the public policy name is unsafe, a numeric
/// value exceeds the Structured Field integer range, or the decision lacks
/// quota service metadata.
pub fn service_limit(name: &str, decision: &Decision) -> Result<HeaderField, EncodingError> {
    let name = encode_policy_name(name)?;
    let (available, effective_window) = match decision.view() {
        DecisionView::Allowed {
            available,
            replenishes_after,
            ..
        } => (available, replenishes_after),
        DecisionView::Denied { denial } => match denial.quota() {
            Some(denial) => (0, denial.retry_after()),
            None => return Err(EncodingError::UnsupportedDecision),
        },
        DecisionView::ShadowDenied { denial } => (0, denial.retry_after()),
    };
    let available = structured_integer(available)?;
    let effective_window = structured_integer(ceil_seconds(effective_window))?;
    let value = header_value(format!("{name};r={available};t={effective_window}"))?;

    Ok((HeaderName::from_static("ratelimit"), value))
}

fn encode_policy_name(name: &str) -> Result<String, EncodingError> {
    if name.is_empty() {
        return Err(EncodingError::EmptyPolicyName);
    }
    if name.len() > MAX_POLICY_NAME_LENGTH {
        return Err(EncodingError::PolicyNameTooLong {
            actual: name.len(),
            maximum: MAX_POLICY_NAME_LENGTH,
        });
    }

    let mut encoded = String::with_capacity(name.len() + 2);
    encoded.push('"');
    for (index, character) in name.char_indices() {
        if !matches!(character, '\u{20}'..='\u{7e}') {
            return Err(EncodingError::InvalidPolicyNameCharacter { index, character });
        }
        if matches!(character, '"' | '\\') {
            encoded.push('\\');
        }
        encoded.push(character);
    }
    encoded.push('"');
    Ok(encoded)
}

fn structured_integer(value: u64) -> Result<u64, EncodingError> {
    if value > MAX_STRUCTURED_FIELD_INTEGER {
        return Err(EncodingError::StructuredFieldIntegerTooLarge {
            actual: value,
            maximum: MAX_STRUCTURED_FIELD_INTEGER,
        });
    }
    Ok(value)
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

fn header_value(value: String) -> Result<HeaderValue, EncodingError> {
    HeaderValue::try_from(value).map_err(|_| EncodingError::InvalidHeaderValue)
}

/// Failure to encode draft-11 response metadata.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum EncodingError {
    /// The public policy name was empty.
    #[error("RateLimit policy name must not be empty")]
    EmptyPolicyName,
    /// The public policy name exceeded [`MAX_POLICY_NAME_LENGTH`].
    #[error("RateLimit policy name is {actual} bytes; the maximum is {maximum}")]
    PolicyNameTooLong {
        /// Supplied byte length.
        actual: usize,
        /// Largest accepted byte length.
        maximum: usize,
    },
    /// The public policy name contained a character outside visible ASCII.
    #[error(
        "RateLimit policy name contains invalid character {character:?} at byte index {index}; \
         use visible ASCII"
    )]
    InvalidPolicyNameCharacter {
        /// Zero-based byte index of the invalid character.
        index: usize,
        /// Invalid character.
        character: char,
    },
    /// A value exceeded the RFC 9651 Structured Field integer range.
    #[error("Structured Field integer {actual} exceeds maximum {maximum}")]
    StructuredFieldIntegerTooLarge {
        /// Supplied integer.
        actual: u64,
        /// Largest representable integer.
        maximum: u64,
    },
    /// The policy's replenishment period was zero.
    #[error("RateLimit-Policy quota period must be greater than zero")]
    ZeroQuotaPeriod,
    /// The policy's replenishment period was not an exact whole second.
    #[error("RateLimit-Policy quota period {actual:?} is not an exact whole number of seconds")]
    QuotaPeriodNotWholeSeconds {
        /// Supplied quota period.
        actual: Duration,
    },
    /// The decision did not describe an allowed allowance or quota denial.
    #[error("the decision cannot be represented as a RateLimit quota service limit")]
    UnsupportedDecision,
    /// A validated field unexpectedly failed the HTTP value grammar.
    #[error("encoded RateLimit metadata is not a valid HTTP header value")]
    InvalidHeaderValue,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use runlimit_core::{
        Decision, Denial, FixedWindowPolicy, GcraPolicy, PolicyFingerprint, PolicyId, QuotaDenial,
        QuotaMode, RateLimitPolicy, ScopeId,
    };

    use super::{
        EncodingError, MAX_POLICY_NAME_LENGTH, MAX_STRUCTURED_FIELD_INTEGER, quota_policy,
        service_limit,
    };

    fn fixed_policy(limit: u64, window: Duration) -> FixedWindowPolicy {
        FixedWindowPolicy::new(
            PolicyId::new("api.search").unwrap(),
            ScopeId::new("client").unwrap(),
            limit,
            window,
        )
        .unwrap()
    }

    #[derive(Debug)]
    struct PeriodOverride {
        policy: FixedWindowPolicy,
        period: Duration,
    }

    impl RateLimitPolicy for PeriodOverride {
        fn id(&self) -> &PolicyId {
            self.policy.id()
        }

        fn scope(&self) -> &ScopeId {
            self.policy.scope()
        }

        fn quota(&self) -> u64 {
            self.policy.limit()
        }

        fn quota_period(&self) -> Duration {
            self.period
        }

        fn capacity(&self) -> u64 {
            self.policy.limit()
        }

        fn fingerprint(&self) -> PolicyFingerprint {
            self.policy.fingerprint()
        }

        fn quota_mode(&self) -> QuotaMode {
            self.policy.quota_mode()
        }
    }

    #[test]
    fn encodes_exact_draft_11_golden_fields() {
        let policy = fixed_policy(100, Duration::from_secs(60));
        let policy_field = quota_policy("search", &policy).unwrap();
        let service_field = service_limit(
            "search",
            &Decision::allowed(100, 49, Duration::from_secs(37)),
        )
        .unwrap();

        assert_eq!(policy_field.0.as_str(), "ratelimit-policy");
        assert_eq!(policy_field.1, "\"search\";q=100;w=60");
        assert_eq!(service_field.0.as_str(), "ratelimit");
        assert_eq!(service_field.1, "\"search\";r=49;t=37");
    }

    #[test]
    fn uses_algorithm_neutral_gcra_policy_metadata() {
        let policy = GcraPolicy::new(
            PolicyId::new("api.upload").unwrap(),
            ScopeId::new("account").unwrap(),
            10,
            Duration::from_secs(60),
            4,
        )
        .unwrap();

        assert_eq!(
            quota_policy("upload", &policy).unwrap().1,
            "\"upload\";q=10;w=60"
        );
    }

    #[test]
    fn quota_and_shadow_denials_are_would_deny_service_values() {
        let denial = QuotaDenial::try_new(10, Duration::from_millis(1_001)).unwrap();

        assert_eq!(
            service_limit("default", &Decision::denied(denial))
                .unwrap()
                .1,
            "\"default\";r=0;t=2"
        );
        assert_eq!(
            service_limit("default", &Decision::shadow_denied(denial))
                .unwrap()
                .1,
            "\"default\";r=0;t=2"
        );
    }

    #[test]
    fn rounds_allowed_effective_windows_up_to_whole_seconds() {
        let decision = Decision::allowed(10, 9, Duration::from_nanos(1));

        assert_eq!(
            service_limit("default", &decision).unwrap().1,
            "\"default\";r=9;t=1"
        );
    }

    #[test]
    fn escapes_structured_field_strings_without_header_injection() {
        let policy = fixed_policy(5, Duration::from_secs(1));

        assert_eq!(
            quota_policy("quoted \"name\" \\ path", &policy).unwrap().1,
            "\"quoted \\\"name\\\" \\\\ path\";q=5;w=1"
        );
        assert_eq!(
            quota_policy("bad\r\ninjected: value", &policy),
            Err(EncodingError::InvalidPolicyNameCharacter {
                index: 3,
                character: '\r',
            })
        );
        assert_eq!(
            quota_policy("café", &policy),
            Err(EncodingError::InvalidPolicyNameCharacter {
                index: 3,
                character: 'é',
            })
        );
    }

    #[test]
    fn rejects_empty_and_oversized_policy_names() {
        let policy = fixed_policy(5, Duration::from_secs(1));

        assert_eq!(
            quota_policy("", &policy),
            Err(EncodingError::EmptyPolicyName)
        );
        assert_eq!(
            quota_policy(&"a".repeat(MAX_POLICY_NAME_LENGTH + 1), &policy),
            Err(EncodingError::PolicyNameTooLong {
                actual: MAX_POLICY_NAME_LENGTH + 1,
                maximum: MAX_POLICY_NAME_LENGTH,
            })
        );
    }

    #[test]
    fn accepts_the_structured_field_integer_maximum_and_rejects_larger_values() {
        let maximum = fixed_policy(MAX_STRUCTURED_FIELD_INTEGER, Duration::from_secs(1));
        let too_large = fixed_policy(MAX_STRUCTURED_FIELD_INTEGER + 1, Duration::from_secs(1));

        assert_eq!(
            quota_policy("maximum", &maximum).unwrap().1,
            "\"maximum\";q=999999999999999;w=1"
        );
        assert_eq!(
            quota_policy("too-large", &too_large),
            Err(EncodingError::StructuredFieldIntegerTooLarge {
                actual: MAX_STRUCTURED_FIELD_INTEGER + 1,
                maximum: MAX_STRUCTURED_FIELD_INTEGER,
            })
        );
        assert_eq!(
            service_limit(
                "too-large",
                &Decision::allowed(
                    MAX_STRUCTURED_FIELD_INTEGER + 1,
                    MAX_STRUCTURED_FIELD_INTEGER + 1,
                    Duration::from_secs(1),
                ),
            ),
            Err(EncodingError::StructuredFieldIntegerTooLarge {
                actual: MAX_STRUCTURED_FIELD_INTEGER + 1,
                maximum: MAX_STRUCTURED_FIELD_INTEGER,
            })
        );
    }

    #[test]
    fn rejects_non_whole_second_policy_periods() {
        let policy = fixed_policy(5, Duration::from_millis(1_500));

        assert_eq!(
            quota_policy("fractional", &policy),
            Err(EncodingError::QuotaPeriodNotWholeSeconds {
                actual: Duration::from_millis(1_500),
            })
        );
    }

    #[test]
    fn rejects_zero_policy_periods_from_custom_policies() {
        let policy = PeriodOverride {
            policy: fixed_policy(5, Duration::from_secs(1)),
            period: Duration::ZERO,
        };

        assert_eq!(
            quota_policy("zero", &policy),
            Err(EncodingError::ZeroQuotaPeriod)
        );
    }

    #[test]
    fn rejects_capacity_denials_as_quota_service_limits() {
        let decision = Decision::denied(Denial::storage_capacity(Some(Duration::from_secs(1))));
        assert_eq!(
            service_limit("default", &decision),
            Err(EncodingError::UnsupportedDecision)
        );
    }

    #[test]
    fn rejects_effective_windows_above_the_structured_field_integer_maximum() {
        let decision =
            Decision::allowed(1, 0, Duration::from_secs(MAX_STRUCTURED_FIELD_INTEGER + 1));

        assert_eq!(
            service_limit("default", &decision),
            Err(EncodingError::StructuredFieldIntegerTooLarge {
                actual: MAX_STRUCTURED_FIELD_INTEGER + 1,
                maximum: MAX_STRUCTURED_FIELD_INTEGER,
            })
        );
    }
}
