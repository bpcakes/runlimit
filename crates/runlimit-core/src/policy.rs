use std::{fmt, num::NonZeroU64, time::Duration};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PolicyId, ScopeId};

const FIXED_WINDOW_FINGERPRINT_DOMAIN: &[u8] = b"runlimit/fixed-window-policy/v1\0";
const GCRA_FINGERPRINT_DOMAIN: &[u8] = b"runlimit/gcra-policy/v1\0";
const MAX_EXACT_DOUBLE_INTEGER: u64 = 1_u64 << f64::MANTISSA_DIGITS;

/// Largest quota or immediate capacity supported by built-in policies.
///
/// The portable ceiling is the largest positive value representable by the
/// signed 64-bit counters used by persistent backends.
pub const MAX_LIMIT: u64 = i64::MAX as u64;

/// Largest whole-millisecond policy duration supported by built-in policies.
///
/// This deliberately conservative ceiling keeps the equivalent microsecond
/// count in the consecutive-integer range of common backend time
/// representations while still allowing durations of roughly 285 years.
pub const MAX_WINDOW_MILLIS: u64 = MAX_EXACT_DOUBLE_INTEGER / 1_000;

/// Largest policy duration supported by built-in policies.
pub const MAX_WINDOW: Duration = Duration::from_millis(MAX_WINDOW_MILLIS);

/// Whether quota exhaustion is enforced or reported in shadow mode.
///
/// This deployment flag is deliberately not part of a policy fingerprint.
/// Switching a policy from [`QuotaMode::Shadow`] to [`QuotaMode::Enforce`]
/// therefore keeps the counter state warmed while it was shadowed.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
pub enum QuotaMode {
    /// Quota exhaustion denies the operation.
    #[default]
    Enforce,
    /// Quota exhaustion is reported but permits the operation to proceed.
    Shadow,
}

/// Backend-independent policy metadata required to construct a check.
///
/// Storage backends remain free to support one specific policy algorithm by
/// choosing it as [`crate::Limiter::Policy`]. Application adapters can be
/// generic over this trait without assuming fixed-window behavior.
pub trait RateLimitPolicy: fmt::Debug + Send + Sync {
    /// Returns the application-defined policy identifier.
    fn id(&self) -> &PolicyId;

    /// Returns the application-defined policy scope.
    fn scope(&self) -> &ScopeId;

    /// Returns the quota replenished during [`Self::quota_period`].
    fn quota(&self) -> u64;

    /// Returns the period during which [`Self::quota`] is replenished.
    fn quota_period(&self) -> Duration;

    /// Returns the largest single cost and maximum immediately available
    /// allowance supported by this policy.
    fn capacity(&self) -> u64;

    /// Returns the deterministic storage-key fingerprint.
    fn fingerprint(&self) -> PolicyFingerprint;

    /// Returns whether quota exhaustion is enforced or shadowed.
    fn quota_mode(&self) -> QuotaMode;
}

/// A deterministic digest of a policy's identity, scope, and configuration.
///
/// Storage backends include this value in counter keys. Consequently, changing
/// any storage-relevant policy configuration starts an independent counter
/// instead of reinterpreting existing state.
///
/// This storage-key component deliberately does not implement Serde traits.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyFingerprint([u8; 32]);

impl PolicyFingerprint {
    /// Constructs a fingerprint from an already domain-separated digest.
    ///
    /// This is intended for third-party [`RateLimitPolicy`] implementations.
    /// The digest must cover the algorithm identity and every
    /// storage-relevant policy field. Deployment-only fields such as
    /// [`QuotaMode`] should be excluded so a mode change reuses warmed state.
    ///
    /// Built-in policies derive their fingerprints automatically.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the 32-byte SHA-256 fingerprint.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the value and returns the 32-byte SHA-256 fingerprint.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for PolicyFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PolicyFingerprint(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

impl fmt::Display for PolicyFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0)
    }
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// An anchored fixed-window rate-limit policy.
///
/// A backend starts a window on the first allowed check for a storage key.
/// Later allowed checks use that anchor until the full window has elapsed.
/// This differs from fixed wall-clock boundaries such as calendar minutes.
///
/// Windows have exact whole-millisecond precision. A policy owns its
/// application-defined identifier and scope so it can be reused by checks.
///
/// With the `serde` feature, the wire object contains `id`, `scope`, `limit`,
/// `window_millis`, and `quota_mode`. The derived fingerprint is deliberately
/// omitted and recomputed through [`FixedWindowPolicy::new`] when
/// deserializing. An omitted `quota_mode` defaults to enforcement.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FixedWindowPolicy {
    id: PolicyId,
    scope: ScopeId,
    limit: NonZeroU64,
    window_millis: NonZeroU64,
    fingerprint: PolicyFingerprint,
    quota_mode: QuotaMode,
}

impl FixedWindowPolicy {
    /// Validates and constructs an anchored fixed-window policy.
    ///
    /// # Errors
    ///
    /// Returns an error if `limit` or `window` is zero, if `limit` exceeds
    /// [`MAX_LIMIT`], if the window is not an exact whole number of
    /// milliseconds, or if it exceeds [`MAX_WINDOW`].
    pub fn new(
        id: PolicyId,
        scope: ScopeId,
        limit: u64,
        window: Duration,
    ) -> Result<Self, PolicyError> {
        let limit = NonZeroU64::new(limit).ok_or(PolicyError::ZeroLimit)?;
        if limit.get() > MAX_LIMIT {
            return Err(PolicyError::LimitTooLarge {
                actual: limit.get(),
                maximum: MAX_LIMIT,
            });
        }
        let window_millis = validate_window(window)?;
        let fingerprint = fingerprint(&id, &scope, limit, window_millis);

        Ok(Self {
            id,
            scope,
            limit,
            window_millis,
            fingerprint,
            quota_mode: QuotaMode::Enforce,
        })
    }

    /// Returns this policy with the requested quota deployment mode.
    ///
    /// The policy fingerprint is unchanged because the mode is not
    /// storage-relevant.
    #[must_use]
    pub const fn with_quota_mode(mut self, quota_mode: QuotaMode) -> Self {
        self.quota_mode = quota_mode;
        self
    }

    /// Returns the application-defined policy identifier.
    pub const fn id(&self) -> &PolicyId {
        &self.id
    }

    /// Returns the application-defined policy scope.
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }

    /// Returns the maximum cost allowed during one window.
    pub const fn limit(&self) -> u64 {
        self.limit.get()
    }

    /// Returns the anchored window duration.
    pub const fn window(&self) -> Duration {
        Duration::from_millis(self.window_millis.get())
    }

    /// Returns the anchored window as an exact, nonzero millisecond count.
    pub const fn window_millis(&self) -> u64 {
        self.window_millis.get()
    }

    /// Returns the deterministic configuration fingerprint.
    pub const fn fingerprint(&self) -> PolicyFingerprint {
        self.fingerprint
    }

    /// Returns whether quota exhaustion is enforced or shadowed.
    pub const fn quota_mode(&self) -> QuotaMode {
        self.quota_mode
    }
}

impl RateLimitPolicy for FixedWindowPolicy {
    fn id(&self) -> &PolicyId {
        self.id()
    }

    fn scope(&self) -> &ScopeId {
        self.scope()
    }

    fn quota(&self) -> u64 {
        self.limit()
    }

    fn quota_period(&self) -> Duration {
        self.window()
    }

    fn capacity(&self) -> u64 {
        self.limit()
    }

    fn fingerprint(&self) -> PolicyFingerprint {
        self.fingerprint()
    }

    fn quota_mode(&self) -> QuotaMode {
        self.quota_mode()
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct FixedWindowPolicyRef<'a> {
    id: &'a PolicyId,
    scope: &'a ScopeId,
    limit: u64,
    window_millis: u64,
    quota_mode: QuotaMode,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedWindowPolicyWire {
    id: PolicyId,
    scope: ScopeId,
    limit: u64,
    window_millis: u64,
    #[serde(default)]
    quota_mode: QuotaMode,
}

#[cfg(feature = "serde")]
impl serde::Serialize for FixedWindowPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(
            &FixedWindowPolicyRef {
                id: self.id(),
                scope: self.scope(),
                limit: self.limit(),
                window_millis: self.window_millis(),
                quota_mode: self.quota_mode(),
            },
            serializer,
        )
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for FixedWindowPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = <FixedWindowPolicyWire as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.scope,
            wire.limit,
            Duration::from_millis(wire.window_millis),
        )
        .map(|policy| policy.with_quota_mode(wire.quota_mode))
        .map_err(serde::de::Error::custom)
    }
}

fn validate_window(window: Duration) -> Result<NonZeroU64, PolicyError> {
    if window.is_zero() {
        return Err(PolicyError::ZeroWindow);
    }
    if !window.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(PolicyError::WindowNotWholeMilliseconds);
    }
    if window > MAX_WINDOW {
        return Err(PolicyError::WindowTooLarge {
            actual: window,
            maximum: MAX_WINDOW,
        });
    }

    let millis =
        u64::try_from(window.as_millis()).expect("the portable window maximum fits in u64");
    NonZeroU64::new(millis).ok_or(PolicyError::ZeroWindow)
}

fn fingerprint(
    id: &PolicyId,
    scope: &ScopeId,
    limit: NonZeroU64,
    window_millis: NonZeroU64,
) -> PolicyFingerprint {
    let mut digest = Sha256::new();
    digest.update(FIXED_WINDOW_FINGERPRINT_DOMAIN);
    digest.update(id.as_str().as_bytes());
    digest.update([0]);
    digest.update(scope.as_str().as_bytes());
    digest.update([0]);
    digest.update(limit.get().to_be_bytes());
    digest.update(window_millis.get().to_be_bytes());
    PolicyFingerprint(digest.finalize().into())
}

/// A generic-cell-rate-algorithm policy.
///
/// `quota` units are replenished uniformly during `period`, while
/// `burst_capacity` controls the maximum immediately available allowance. This
/// avoids fixed-window boundary bursts while retaining constant-size state per
/// storage key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GcraPolicy {
    id: PolicyId,
    scope: ScopeId,
    quota: NonZeroU64,
    period_millis: NonZeroU64,
    burst_capacity: NonZeroU64,
    fingerprint: PolicyFingerprint,
    quota_mode: QuotaMode,
}

impl GcraPolicy {
    /// Validates and constructs a GCRA policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the quota or burst capacity is zero or exceeds
    /// [`MAX_LIMIT`], or when the period is not a supported exact
    /// whole-millisecond duration.
    pub fn new(
        id: PolicyId,
        scope: ScopeId,
        quota: u64,
        period: Duration,
        burst_capacity: u64,
    ) -> Result<Self, GcraPolicyError> {
        let quota = NonZeroU64::new(quota).ok_or(GcraPolicyError::ZeroQuota)?;
        if quota.get() > MAX_LIMIT {
            return Err(GcraPolicyError::QuotaTooLarge {
                actual: quota.get(),
                maximum: MAX_LIMIT,
            });
        }
        let burst_capacity =
            NonZeroU64::new(burst_capacity).ok_or(GcraPolicyError::ZeroBurstCapacity)?;
        if burst_capacity.get() > MAX_LIMIT {
            return Err(GcraPolicyError::BurstCapacityTooLarge {
                actual: burst_capacity.get(),
                maximum: MAX_LIMIT,
            });
        }
        let period_millis = validate_window(period).map_err(GcraPolicyError::from)?;
        let full_refill_millis = div_ceil_u128(
            u128::from(burst_capacity.get()) * u128::from(period_millis.get()),
            u128::from(quota.get()),
        );
        if full_refill_millis > u128::from(MAX_WINDOW_MILLIS) {
            return Err(GcraPolicyError::RefillDurationTooLarge {
                actual_millis: full_refill_millis,
                maximum_millis: MAX_WINDOW_MILLIS,
            });
        }
        let fingerprint = gcra_fingerprint(&id, &scope, quota, period_millis, burst_capacity);

        Ok(Self {
            id,
            scope,
            quota,
            period_millis,
            burst_capacity,
            fingerprint,
            quota_mode: QuotaMode::Enforce,
        })
    }

    /// Returns this policy with the requested quota deployment mode.
    #[must_use]
    pub const fn with_quota_mode(mut self, quota_mode: QuotaMode) -> Self {
        self.quota_mode = quota_mode;
        self
    }

    /// Returns the application-defined policy identifier.
    pub const fn id(&self) -> &PolicyId {
        &self.id
    }

    /// Returns the application-defined policy scope.
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }

    /// Returns the number of units replenished during one period.
    pub const fn quota(&self) -> u64 {
        self.quota.get()
    }

    /// Returns the replenishment period.
    pub const fn period(&self) -> Duration {
        Duration::from_millis(self.period_millis.get())
    }

    /// Returns the replenishment period as exact whole milliseconds.
    pub const fn period_millis(&self) -> u64 {
        self.period_millis.get()
    }

    /// Returns the maximum immediately available allowance.
    pub const fn burst_capacity(&self) -> u64 {
        self.burst_capacity.get()
    }

    /// Returns the deterministic configuration fingerprint.
    pub const fn fingerprint(&self) -> PolicyFingerprint {
        self.fingerprint
    }

    /// Returns whether quota exhaustion is enforced or shadowed.
    pub const fn quota_mode(&self) -> QuotaMode {
        self.quota_mode
    }
}

impl RateLimitPolicy for GcraPolicy {
    fn id(&self) -> &PolicyId {
        self.id()
    }

    fn scope(&self) -> &ScopeId {
        self.scope()
    }

    fn quota(&self) -> u64 {
        self.quota()
    }

    fn quota_period(&self) -> Duration {
        self.period()
    }

    fn capacity(&self) -> u64 {
        self.burst_capacity()
    }

    fn fingerprint(&self) -> PolicyFingerprint {
        self.fingerprint()
    }

    fn quota_mode(&self) -> QuotaMode {
        self.quota_mode()
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct GcraPolicyRef<'a> {
    id: &'a PolicyId,
    scope: &'a ScopeId,
    quota: u64,
    period_millis: u64,
    burst_capacity: u64,
    quota_mode: QuotaMode,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GcraPolicyWire {
    id: PolicyId,
    scope: ScopeId,
    quota: u64,
    period_millis: u64,
    burst_capacity: u64,
    #[serde(default)]
    quota_mode: QuotaMode,
}

#[cfg(feature = "serde")]
impl serde::Serialize for GcraPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(
            &GcraPolicyRef {
                id: self.id(),
                scope: self.scope(),
                quota: self.quota(),
                period_millis: self.period_millis(),
                burst_capacity: self.burst_capacity(),
                quota_mode: self.quota_mode(),
            },
            serializer,
        )
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for GcraPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = <GcraPolicyWire as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.scope,
            wire.quota,
            Duration::from_millis(wire.period_millis),
            wire.burst_capacity,
        )
        .map(|policy| policy.with_quota_mode(wire.quota_mode))
        .map_err(serde::de::Error::custom)
    }
}

fn gcra_fingerprint(
    id: &PolicyId,
    scope: &ScopeId,
    quota: NonZeroU64,
    period_millis: NonZeroU64,
    burst_capacity: NonZeroU64,
) -> PolicyFingerprint {
    let mut digest = Sha256::new();
    digest.update(GCRA_FINGERPRINT_DOMAIN);
    digest.update(id.as_str().as_bytes());
    digest.update([0]);
    digest.update(scope.as_str().as_bytes());
    digest.update([0]);
    digest.update(quota.get().to_be_bytes());
    digest.update(period_millis.get().to_be_bytes());
    digest.update(burst_capacity.get().to_be_bytes());
    PolicyFingerprint(digest.finalize().into())
}

const fn div_ceil_u128(numerator: u128, denominator: u128) -> u128 {
    numerator / denominator
        + if numerator.is_multiple_of(denominator) {
            0
        } else {
            1
        }
}

/// An invalid fixed-window policy configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    /// The configured limit was zero.
    #[error("fixed-window limit must be greater than zero")]
    ZeroLimit,
    /// The configured limit exceeded the portable backend maximum.
    #[error("fixed-window limit {actual} exceeds portable maximum {maximum}")]
    LimitTooLarge {
        /// Supplied limit.
        actual: u64,
        /// Largest limit supported by every backend.
        maximum: u64,
    },
    /// The configured window was zero.
    #[error("fixed-window duration must be greater than zero")]
    ZeroWindow,
    /// The configured window had finer precision than a whole millisecond.
    #[error("fixed-window duration must be an exact whole number of milliseconds")]
    WindowNotWholeMilliseconds,
    /// The configured window exceeded the portable backend maximum.
    #[error("fixed-window duration {actual:?} exceeds portable maximum {maximum:?}")]
    WindowTooLarge {
        /// Supplied window.
        actual: Duration,
        /// Largest window supported by every backend.
        maximum: Duration,
    },
}

/// An invalid GCRA policy configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum GcraPolicyError {
    /// The replenishment quota was zero.
    #[error("GCRA quota must be greater than zero")]
    ZeroQuota,
    /// The replenishment quota exceeded the portable backend maximum.
    #[error("GCRA quota {actual} exceeds portable maximum {maximum}")]
    QuotaTooLarge {
        /// Supplied quota.
        actual: u64,
        /// Largest quota supported by every backend.
        maximum: u64,
    },
    /// The burst capacity was zero.
    #[error("GCRA burst capacity must be greater than zero")]
    ZeroBurstCapacity,
    /// The burst capacity exceeded the portable backend maximum.
    #[error("GCRA burst capacity {actual} exceeds portable maximum {maximum}")]
    BurstCapacityTooLarge {
        /// Supplied burst capacity.
        actual: u64,
        /// Largest burst capacity supported by every backend.
        maximum: u64,
    },
    /// The replenishment period was zero.
    #[error("GCRA period must be greater than zero")]
    ZeroPeriod,
    /// The replenishment period had finer precision than a millisecond.
    #[error("GCRA period must be an exact whole number of milliseconds")]
    PeriodNotWholeMilliseconds,
    /// The replenishment period exceeded the portable backend maximum.
    #[error("GCRA period {actual:?} exceeds portable maximum {maximum:?}")]
    PeriodTooLarge {
        /// Supplied period.
        actual: Duration,
        /// Largest supported period.
        maximum: Duration,
    },
    /// Filling the complete burst would take longer than the portable maximum.
    #[error(
        "GCRA full-refill duration {actual_millis}ms exceeds portable maximum {maximum_millis}ms"
    )]
    RefillDurationTooLarge {
        /// Computed full-refill duration in milliseconds.
        actual_millis: u128,
        /// Largest supported full-refill duration in milliseconds.
        maximum_millis: u64,
    },
}

impl From<PolicyError> for GcraPolicyError {
    fn from(error: PolicyError) -> Self {
        match error {
            PolicyError::ZeroWindow => Self::ZeroPeriod,
            PolicyError::WindowNotWholeMilliseconds => Self::PeriodNotWholeMilliseconds,
            PolicyError::WindowTooLarge { actual, maximum } => {
                Self::PeriodTooLarge { actual, maximum }
            }
            PolicyError::ZeroLimit | PolicyError::LimitTooLarge { .. } => {
                unreachable!("period validation cannot produce a limit error")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        FixedWindowPolicy, GcraPolicy, GcraPolicyError, MAX_LIMIT, MAX_WINDOW, MAX_WINDOW_MILLIS,
        PolicyError, QuotaMode, RateLimitPolicy,
    };
    use crate::{PolicyId, ScopeId};

    fn policy(limit: u64, window: Duration) -> Result<FixedWindowPolicy, PolicyError> {
        FixedWindowPolicy::new(
            PolicyId::new("auth.login").unwrap(),
            ScopeId::new("client").unwrap(),
            limit,
            window,
        )
    }

    #[test]
    fn accepts_nonzero_whole_millisecond_windows() {
        let policy = policy(8, Duration::from_millis(60_001)).unwrap();

        assert_eq!(policy.limit(), 8);
        assert_eq!(policy.window(), Duration::from_millis(60_001));
        assert_eq!(policy.window_millis(), 60_001);
        assert_eq!(policy.id().as_str(), "auth.login");
        assert_eq!(policy.scope().as_str(), "client");
    }

    #[test]
    fn rejects_zero_limit_and_window() {
        assert_eq!(
            policy(0, Duration::from_secs(1)),
            Err(PolicyError::ZeroLimit)
        );
        assert_eq!(policy(1, Duration::ZERO), Err(PolicyError::ZeroWindow));
    }

    #[test]
    fn rejects_sub_millisecond_and_fractional_millisecond_windows() {
        assert_eq!(
            policy(1, Duration::from_nanos(1)),
            Err(PolicyError::WindowNotWholeMilliseconds)
        );
        assert_eq!(
            policy(1, Duration::from_micros(1_500)),
            Err(PolicyError::WindowNotWholeMilliseconds)
        );
    }

    #[test]
    fn accepts_portable_upper_bounds() {
        let policy = policy(MAX_LIMIT, MAX_WINDOW).unwrap();

        assert_eq!(policy.limit(), MAX_LIMIT);
        assert_eq!(policy.window(), MAX_WINDOW);
        assert_eq!(policy.window_millis(), MAX_WINDOW_MILLIS);
    }

    #[test]
    fn rejects_limit_above_portable_maximum() {
        assert_eq!(
            policy(MAX_LIMIT + 1, Duration::from_secs(1)),
            Err(PolicyError::LimitTooLarge {
                actual: MAX_LIMIT + 1,
                maximum: MAX_LIMIT,
            })
        );
    }

    #[test]
    fn rejects_window_above_portable_maximum() {
        let actual = MAX_WINDOW + Duration::from_millis(1);

        assert_eq!(
            policy(1, actual),
            Err(PolicyError::WindowTooLarge {
                actual,
                maximum: MAX_WINDOW,
            })
        );
    }

    #[test]
    fn rejects_windows_far_beyond_portable_maximum() {
        let actual = Duration::from_secs(u64::MAX);

        assert_eq!(
            policy(1, actual),
            Err(PolicyError::WindowTooLarge {
                actual,
                maximum: MAX_WINDOW,
            })
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let first = policy(8, Duration::from_secs(60)).unwrap();
        let second = policy(8, Duration::from_secs(60)).unwrap();

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().as_bytes().len(), 32);
        assert_eq!(first.fingerprint().to_string().len(), 64);
    }

    #[test]
    fn fingerprint_changes_with_every_storage_relevant_field() {
        let baseline = policy(8, Duration::from_secs(60)).unwrap();
        let different_limit = policy(9, Duration::from_secs(60)).unwrap();
        let different_window = policy(8, Duration::from_secs(61)).unwrap();
        let different_id = FixedWindowPolicy::new(
            PolicyId::new("auth.signup").unwrap(),
            ScopeId::new("client").unwrap(),
            8,
            Duration::from_secs(60),
        )
        .unwrap();
        let different_scope = FixedWindowPolicy::new(
            PolicyId::new("auth.login").unwrap(),
            ScopeId::new("identity").unwrap(),
            8,
            Duration::from_secs(60),
        )
        .unwrap();

        assert_ne!(baseline.fingerprint(), different_limit.fingerprint());
        assert_ne!(baseline.fingerprint(), different_window.fingerprint());
        assert_ne!(baseline.fingerprint(), different_id.fingerprint());
        assert_ne!(baseline.fingerprint(), different_scope.fingerprint());
    }

    #[test]
    fn quota_mode_does_not_change_fixed_window_storage_identity() {
        let enforced = policy(8, Duration::from_secs(60)).unwrap();
        let shadowed = enforced.clone().with_quota_mode(QuotaMode::Shadow);

        assert_eq!(enforced.fingerprint(), shadowed.fingerprint());
        assert_eq!(enforced.quota_mode(), QuotaMode::Enforce);
        assert_eq!(shadowed.quota_mode(), QuotaMode::Shadow);
        assert_eq!(RateLimitPolicy::capacity(&shadowed), 8);
    }

    #[test]
    fn gcra_policy_exposes_uniform_replenishment_and_distinct_fingerprint() {
        let id = PolicyId::new("api.read").unwrap();
        let scope = ScopeId::new("account").unwrap();
        let gcra =
            GcraPolicy::new(id.clone(), scope.clone(), 10, Duration::from_secs(1), 20).unwrap();
        let fixed = FixedWindowPolicy::new(id, scope, 10, Duration::from_secs(1)).unwrap();

        assert_eq!(gcra.quota(), 10);
        assert_eq!(gcra.period(), Duration::from_secs(1));
        assert_eq!(gcra.burst_capacity(), 20);
        assert_eq!(RateLimitPolicy::capacity(&gcra), 20);
        assert_ne!(gcra.fingerprint(), fixed.fingerprint());
        assert_eq!(
            gcra.fingerprint(),
            gcra.clone()
                .with_quota_mode(QuotaMode::Shadow)
                .fingerprint()
        );
    }

    #[test]
    fn gcra_fingerprint_tracks_every_storage_field_but_not_quota_mode() {
        let make = |id: &str, scope: &str, quota, period_millis, burst_capacity| {
            GcraPolicy::new(
                PolicyId::new(id).unwrap(),
                ScopeId::new(scope).unwrap(),
                quota,
                Duration::from_millis(period_millis),
                burst_capacity,
            )
            .unwrap()
        };
        let baseline = make("api.read", "account", 10, 1_000, 20);

        assert_eq!(
            baseline.fingerprint(),
            make("api.read", "account", 10, 1_000, 20).fingerprint()
        );
        assert_ne!(
            baseline.fingerprint(),
            make("api.write", "account", 10, 1_000, 20).fingerprint()
        );
        assert_ne!(
            baseline.fingerprint(),
            make("api.read", "client", 10, 1_000, 20).fingerprint()
        );
        assert_ne!(
            baseline.fingerprint(),
            make("api.read", "account", 11, 1_000, 20).fingerprint()
        );
        assert_ne!(
            baseline.fingerprint(),
            make("api.read", "account", 10, 1_001, 20).fingerprint()
        );
        assert_ne!(
            baseline.fingerprint(),
            make("api.read", "account", 10, 1_000, 21).fingerprint()
        );
        assert_eq!(
            baseline.fingerprint(),
            baseline
                .clone()
                .with_quota_mode(QuotaMode::Shadow)
                .fingerprint()
        );
    }

    #[test]
    fn gcra_policy_rejects_invalid_portable_values() {
        let make = |quota, period, burst| {
            GcraPolicy::new(
                PolicyId::new("api.read").unwrap(),
                ScopeId::new("account").unwrap(),
                quota,
                period,
                burst,
            )
        };

        assert_eq!(
            make(0, Duration::from_secs(1), 1),
            Err(GcraPolicyError::ZeroQuota)
        );
        assert_eq!(
            make(1, Duration::from_secs(1), 0),
            Err(GcraPolicyError::ZeroBurstCapacity)
        );
        assert_eq!(
            make(1, Duration::from_nanos(1), 1),
            Err(GcraPolicyError::PeriodNotWholeMilliseconds)
        );
        assert!(matches!(
            make(1, MAX_WINDOW, 2),
            Err(GcraPolicyError::RefillDurationTooLarge { .. })
        ));
    }
}
