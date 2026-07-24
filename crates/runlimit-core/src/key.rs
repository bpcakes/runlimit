use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{FixedWindowPolicy, PolicyId, ScopeId};

const KEY_DOMAIN: &[u8] = b"runlimit/subject-key/v1\0";

type HmacSha256 = Hmac<Sha256>;

/// An opaque, fixed-width subject identifier used by storage backends.
///
/// The inner digest is intentionally omitted from [`Debug`] output. Construct
/// keys with [`KeyHasher`] unless the input is already a cryptographically
/// opaque 32-byte digest.
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
pub struct KeyHasher {
    secret: Zeroizing<Vec<u8>>,
}

impl KeyHasher {
    /// Minimum accepted secret length in bytes.
    pub const MINIMUM_SECRET_LENGTH: usize = 32;

    /// Constructs a hasher by copying a secret into zeroizing storage.
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

        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
        })
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
        // Construct this state per derivation: hmac 0.12's cloneable keyed
        // state does not implement Zeroize, so caching it would retain a
        // second long-lived, key-equivalent secret outside `self.secret`.
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.secret) else {
            unreachable!("HMAC-SHA-256 accepts keys of every length");
        };
        mac.update(KEY_DOMAIN);
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
}
