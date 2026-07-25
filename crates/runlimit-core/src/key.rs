use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;

use crate::{FixedWindowPolicy, PolicyId, ScopeId};

const KEY_DOMAIN: &[u8] = b"runlimit/subject-key/v1\0";

type HmacSha256 = Hmac<Sha256>;

/// An opaque, fixed-width subject identifier used by storage backends.
///
/// The inner digest is intentionally omitted from [`Debug`] output. Construct
/// keys with [`KeyHasher`] unless the input is already a cryptographically
/// opaque 32-byte digest.
///
/// This type deliberately does not implement Serde traits, even when the
/// crate's `serde` feature is enabled, to avoid accidental key disclosure.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubjectKey([u8; 32]);

impl SubjectKey {
    /// Constructs a key from an already-opaque 32-byte digest.
    ///
    /// This constructor does not hash or otherwise transform the input.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the opaque digest bytes for storage and comparison.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the key and returns its opaque digest bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SubjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectKey([REDACTED])")
    }
}

/// Derives opaque subject keys using HMAC-SHA-256.
///
/// Each derivation is domain-separated by the exact policy and scope
/// identifiers. The same normalized subject therefore yields unrelated keys
/// in different policy scopes.
///
/// Applications should keep one stable secret per deployment. Rotating it
/// deliberately starts new counters because all derived subject keys change.
///
/// The raw secret is not retained after construction. Instead, the hasher
/// caches key-equivalent, precomputed HMAC state. Cloning a hasher copies that
/// state; each copy zeroizes its SHA-256 state and buffered input when dropped.
/// Treat a live [`KeyHasher`] as secret material. [`Debug`](fmt::Debug) never
/// exposes its state.
pub struct KeyHasher {
    template: HmacSha256,
}

impl Clone for KeyHasher {
    fn clone(&self) -> Self {
        Self {
            template: self.template.clone(),
        }
    }
}

impl KeyHasher {
    /// Minimum accepted secret length in bytes.
    pub const MINIMUM_SECRET_LENGTH: usize = 32;

    /// Constructs a hasher by precomputing zeroizing keyed HMAC state.
    ///
    /// The supplied raw secret is borrowed only for construction and is not
    /// retained by the returned hasher.
    ///
    /// # Errors
    ///
    /// Returns [`KeyHasherError::SecretTooShort`] unless the secret contains at
    /// least 32 bytes.
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, KeyHasherError> {
        let secret = secret.as_ref();
        if secret.len() < Self::MINIMUM_SECRET_LENGTH {
            return Err(KeyHasherError::SecretTooShort {
                actual: secret.len(),
                minimum: Self::MINIMUM_SECRET_LENGTH,
            });
        }

        let Ok(mut template) = HmacSha256::new_from_slice(secret) else {
            unreachable!("HMAC-SHA-256 accepts keys of every length");
        };
        template.update(KEY_DOMAIN);

        Ok(Self { template })
    }

    /// Hashes a normalized subject within an explicit policy and scope.
    ///
    /// Normalization is application-owned: two byte strings are treated as
    /// distinct subjects even if an application considers them equivalent.
    pub fn hash(
        &self,
        policy_id: &PolicyId,
        scope_id: &ScopeId,
        subject: impl AsRef<[u8]>,
    ) -> SubjectKey {
        let mut mac = self.template.clone();
        mac.update(policy_id.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(scope_id.as_str().as_bytes());
        mac.update(&[0]);
        mac.update(subject.as_ref());
        SubjectKey::from_digest(mac.finalize().into_bytes().into())
    }

    /// Hashes a normalized subject in a fixed-window policy's namespace.
    pub fn hash_for(&self, policy: &FixedWindowPolicy, subject: impl AsRef<[u8]>) -> SubjectKey {
        self.hash(policy.id(), policy.scope(), subject)
    }
}

impl fmt::Debug for KeyHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyHasher([REDACTED])")
    }
}

/// An invalid subject-key hasher configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum KeyHasherError {
    /// The supplied secret was shorter than the security minimum.
    #[error("key-hashing secret is {actual} bytes; at least {minimum} bytes are required")]
    SecretTooShort {
        /// Supplied secret length.
        actual: usize,
        /// Minimum accepted secret length.
        minimum: usize,
    },
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{KeyHasher, KeyHasherError, SubjectKey};
    use crate::{FixedWindowPolicy, PolicyId, ScopeId};

    fn hasher() -> KeyHasher {
        KeyHasher::new([0x42; 32]).unwrap()
    }

    fn policy(id: &str, scope: &str) -> FixedWindowPolicy {
        FixedWindowPolicy::new(
            PolicyId::new(id).unwrap(),
            ScopeId::new(scope).unwrap(),
            8,
            Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn rejects_short_secrets() {
        assert_eq!(
            KeyHasher::new([0; 31]).unwrap_err(),
            KeyHasherError::SecretTooShort {
                actual: 31,
                minimum: 32,
            }
        );
    }

    #[test]
    fn accepts_secrets_longer_than_the_minimum() {
        assert!(KeyHasher::new([0; 64]).is_ok());
    }

    #[test]
    fn hashing_is_deterministic_within_a_namespace() {
        let policy = policy("auth.login", "identity");
        let first = hasher().hash_for(&policy, b"user@example.test");
        let second = hasher().hash_for(&policy, b"user@example.test");

        assert_eq!(first, second);
    }

    #[test]
    fn policy_and_scope_domain_separate_subjects() {
        let hasher = hasher();
        let login_identity =
            hasher.hash_for(&policy("auth.login", "identity"), b"user@example.test");
        let signup_identity =
            hasher.hash_for(&policy("auth.signup", "identity"), b"user@example.test");
        let login_client = hasher.hash_for(&policy("auth.login", "client"), b"user@example.test");

        assert_ne!(login_identity, signup_identity);
        assert_ne!(login_identity, login_client);
    }

    #[test]
    fn subjects_and_secrets_change_the_digest() {
        let policy = policy("auth.login", "identity");
        let first = hasher().hash_for(&policy, b"first");
        let second = hasher().hash_for(&policy, b"second");
        let other_secret = KeyHasher::new([0x24; 32])
            .unwrap()
            .hash_for(&policy, b"first");

        assert_ne!(first, second);
        assert_ne!(first, other_secret);
    }

    #[test]
    fn subject_key_debug_output_is_redacted() {
        let key = SubjectKey::from_digest([0xab; 32]);
        let output = format!("{key:?}");

        assert_eq!(output, "SubjectKey([REDACTED])");
        assert!(!output.contains("ab"));
        assert_eq!(key.as_bytes(), &[0xab; 32]);
        assert_eq!(key.into_bytes(), [0xab; 32]);
    }

    #[test]
    fn hasher_debug_output_is_redacted() {
        assert_eq!(format!("{:?}", hasher()), "KeyHasher([REDACTED])");
    }

    #[test]
    fn hashing_matches_stable_protocol_vectors() {
        let policy = policy("auth.login", "identity");

        assert_eq!(
            hasher()
                .hash_for(&policy, b"user@example.test")
                .into_bytes(),
            [
                0x7e, 0x8c, 0x35, 0x4d, 0x1a, 0x9b, 0x8c, 0x11, 0xeb, 0xf5, 0xfd, 0x5f, 0xcb, 0x82,
                0x58, 0x6f, 0xda, 0xce, 0xbe, 0xf1, 0xff, 0x15, 0x82, 0x9f, 0xe0, 0xb0, 0x79, 0xd1,
                0x31, 0x22, 0xbc, 0x21,
            ]
        );
        assert_eq!(
            KeyHasher::new([0x24; 80])
                .unwrap()
                .hash_for(&policy, b"user@example.test")
                .into_bytes(),
            [
                0x23, 0xa7, 0x30, 0xd0, 0x57, 0x8e, 0xec, 0x28, 0xe3, 0xf5, 0x7d, 0xd3, 0x96, 0x32,
                0xd8, 0xd8, 0x7b, 0x99, 0x87, 0x79, 0x56, 0xc9, 0xcd, 0x7d, 0xfe, 0x26, 0x84, 0x7b,
                0x17, 0x61, 0x8b, 0xd0,
            ]
        );
    }

    #[test]
    fn cloned_hasher_uses_independently_zeroizing_keyed_state() {
        let policy = policy("auth.login", "identity");
        let original = hasher();
        let cloned = original.clone();
        let expected = original.hash_for(&policy, b"user@example.test");

        drop(original);

        assert_eq!(
            cloned.hash_for(&policy, b"user@example.test"),
            expected,
            "dropping the original must not invalidate the clone"
        );
        assert_eq!(format!("{cloned:?}"), "KeyHasher([REDACTED])");
    }
}
