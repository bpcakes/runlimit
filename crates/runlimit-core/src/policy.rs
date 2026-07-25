use std::{fmt, num::NonZeroU64, time::Duration};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PolicyId, ScopeId};

const FINGERPRINT_DOMAIN: &[u8] = b"runlimit/fixed-window-policy/v1\0";
const MAX_EXACT_DOUBLE_INTEGER: u64 = 1_u64 << f64::MANTISSA_DIGITS;

/// Largest fixed-window quota supported by every Runlimit backend.
///
/// The portable ceiling is the largest positive value representable by the
/// signed 64-bit counters used by persistent backends.
pub const MAX_LIMIT: u64 = i64::MAX as u64;

/// Largest whole-millisecond window supported by every Runlimit backend.
///
/// This deliberately conservative ceiling keeps the equivalent microsecond
/// count in the consecutive-integer range of common backend time
/// representations while still allowing windows of roughly 285 years.
pub const MAX_WINDOW_MILLIS: u64 = MAX_EXACT_DOUBLE_INTEGER / 1_000;

/// Largest fixed-window duration supported by every Runlimit backend.
pub const MAX_WINDOW: Duration = Duration::from_millis(MAX_WINDOW_MILLIS);

/// A deterministic digest of a policy's identity, scope, and configuration.
///
/// Storage backends include this value in counter keys. Consequently, changing
/// a limit or window starts an independent counter instead of reinterpreting
/// state created under the old configuration.
///
/// This storage-key component deliberately does not implement Serde traits.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyFingerprint([u8; 32]);

impl PolicyFingerprint {
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
/// and `window_millis`. The derived fingerprint is deliberately omitted and
/// recomputed through [`FixedWindowPolicy::new`] when deserializing.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FixedWindowPolicy {
    id: PolicyId,
    scope: ScopeId,
    limit: NonZeroU64,
    window_millis: NonZeroU64,
    fingerprint: PolicyFingerprint,
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
        })
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
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
struct FixedWindowPolicyRef<'a> {
    id: &'a PolicyId,
    scope: &'a ScopeId,
    limit: u64,
    window_millis: u64,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedWindowPolicyWire {
    id: PolicyId,
    scope: ScopeId,
    limit: u64,
    window_millis: u64,
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
    digest.update(FINGERPRINT_DOMAIN);
    digest.update(id.as_str().as_bytes());
    digest.update([0]);
    digest.update(scope.as_str().as_bytes());
    digest.update([0]);
    digest.update(limit.get().to_be_bytes());
    digest.update(window_millis.get().to_be_bytes());
    PolicyFingerprint(digest.finalize().into())
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{FixedWindowPolicy, MAX_LIMIT, MAX_WINDOW, MAX_WINDOW_MILLIS, PolicyError};
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
}
