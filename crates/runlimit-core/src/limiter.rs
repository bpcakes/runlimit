use std::{error::Error, future::Future};

use crate::{BatchDecision, Check, Decision};

/// An asynchronous, backend-independent rate limiter.
///
/// Implementations evaluate one check or an atomic batch using their own
/// authoritative time source. The returned futures are [`Send`], so adapters
/// can await them on a multithreaded executor without Runlimit depending on a
/// particular async runtime.
///
/// This trait uses return-position `impl Future` for static dispatch without
/// requiring a boxed future. It is intentionally not object-safe. Applications
/// that need runtime backend selection can implement `Limiter` for an
/// application-owned enum and delegate to each variant. The executor
/// portability guarantee also requires limiter and error types to be [`Send`]
/// and [`Sync`], excluding deliberately single-thread-only implementations.
pub trait Limiter: Send + Sync {
    /// Backend-specific operational failure.
    type Error: Error + Send + Sync + 'static;

    /// Evaluates and, when allowed, consumes one check.
    fn check(
        &self,
        check: &Check<'_>,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send;

    /// Evaluates a batch atomically.
    ///
    /// If any check is denied, no check consumes quota. Allowed decisions
    /// preserve the caller's input order.
    fn check_all(
        &self,
        checks: &[Check<'_>],
    ) -> impl Future<Output = Result<BatchDecision, Self::Error>> + Send;
}
