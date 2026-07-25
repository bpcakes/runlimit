//! Caller-controlled Axum admission middleware for Runlimit.
//!
//! [`RateLimitLayer`] evaluates one [`runlimit_core::Check`] before calling the
//! wrapped service. Applications supply both trust-sensitive operations:
//!
//! - a synchronous [`ExtractSubjectKey`] implementation that derives an opaque
//!   [`runlimit_core::SubjectKey`] from the request; and
//! - a rejection mapper that converts extraction failures, enforced decisions,
//!   and backend failures into an Axum [`Response`].
//!
//! This crate never interprets forwarding headers, connection metadata, or
//! application identities. It also does not select response status codes,
//! bodies, or headers. A shadow denial permits the request and is available to
//! downstream code as a [`runlimit_core::Decision`] request extension, just
//! like an allowed decision.

use std::{
    any::type_name,
    fmt,
    future::Future,
    marker::PhantomData,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{extract::Request, response::Response};
use runlimit_core::{Check, Decision, Limiter, SubjectKey};
use tower::{Layer, Service};

/// A synchronous, application-owned request-to-subject-key boundary.
///
/// The extractor receives the complete request and the configured policy.
/// Implementations decide whether request metadata is trusted and how an
/// application identity is normalized. Closures with the matching signature
/// implement this trait automatically.
///
/// Extractors should return only opaque [`SubjectKey`] values. In particular,
/// raw identities should not cross into a Runlimit backend or generic error
/// and telemetry paths.
pub trait ExtractSubjectKey<P, B>: Send + Sync {
    /// Application-defined extraction failure.
    type Error;

    /// Derives the opaque subject key for this request and policy.
    ///
    /// # Errors
    ///
    /// Returns an application-defined error when the request does not contain
    /// usable or trusted subject material.
    fn extract_subject_key(
        &self,
        request: &Request<B>,
        policy: &P,
    ) -> Result<SubjectKey, Self::Error>;
}

impl<P, B, F, E> ExtractSubjectKey<P, B> for F
where
    F: Fn(&Request<B>, &P) -> Result<SubjectKey, E> + Send + Sync,
{
    type Error = E;

    fn extract_subject_key(
        &self,
        request: &Request<B>,
        policy: &P,
    ) -> Result<SubjectKey, Self::Error> {
        self(request, policy)
    }
}

/// A rate-limit rejection handed to the application-owned response mapper.
///
/// This type deliberately does not implement `IntoResponse`: the application
/// controls its status, response body, headers, and operational-failure
/// policy.
#[non_exhaustive]
pub enum RateLimitRejection<KeyError, BackendError> {
    /// The application-owned key extractor rejected the request.
    Key(KeyError),
    /// The backend returned an enforced quota or storage-capacity denial.
    Denied(Decision),
    /// The backend could not complete the admission check.
    Backend(BackendError),
}

impl<KeyError, BackendError> RateLimitRejection<KeyError, BackendError> {
    /// Returns a stable, non-sensitive label for the rejection category.
    pub const fn kind(&self) -> RejectionKind {
        match self {
            Self::Key(_) => RejectionKind::Key,
            Self::Denied(_) => RejectionKind::Denied,
            Self::Backend(_) => RejectionKind::Backend,
        }
    }
}

impl<KeyError, BackendError> fmt::Debug for RateLimitRejection<KeyError, BackendError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitRejection")
            .field("kind", &self.kind())
            .field("details", &Redacted)
            .finish()
    }
}

/// The non-sensitive category of a [`RateLimitRejection`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RejectionKind {
    /// Subject-key extraction failed.
    Key,
    /// The limiter returned an enforced denial.
    Denied,
    /// The limiter backend failed.
    Backend,
}

/// A Tower layer that performs one Runlimit admission check per request.
///
/// The layer owns one policy and shares the limiter and callback state across
/// clones. It extracts the key and starts the limiter operation before the
/// wrapped service is called. Neither the layer nor its service reads or polls
/// the request body.
pub struct RateLimitLayer<L: Limiter, K, R> {
    limiter: Arc<L>,
    policy: Arc<L::Policy>,
    key_extractor: Arc<K>,
    rejection_mapper: Arc<R>,
}

impl<L: Limiter, K, R> RateLimitLayer<L, K, R> {
    /// Constructs a layer and moves a limiter into shared ownership.
    pub fn new(limiter: L, policy: L::Policy, key_extractor: K, rejection_mapper: R) -> Self {
        Self::from_shared(Arc::new(limiter), policy, key_extractor, rejection_mapper)
    }

    /// Constructs a layer from an already shared limiter.
    pub fn from_shared(
        limiter: Arc<L>,
        policy: L::Policy,
        key_extractor: K,
        rejection_mapper: R,
    ) -> Self {
        Self {
            limiter,
            policy: Arc::new(policy),
            key_extractor: Arc::new(key_extractor),
            rejection_mapper: Arc::new(rejection_mapper),
        }
    }

    /// Returns the shared limiter used by this layer.
    pub const fn limiter(&self) -> &Arc<L> {
        &self.limiter
    }

    /// Returns the policy evaluated for every request.
    pub fn policy(&self) -> &L::Policy {
        self.policy.as_ref()
    }
}

impl<L: Limiter, K, R> Clone for RateLimitLayer<L, K, R> {
    fn clone(&self) -> Self {
        Self {
            limiter: Arc::clone(&self.limiter),
            policy: Arc::clone(&self.policy),
            key_extractor: Arc::clone(&self.key_extractor),
            rejection_mapper: Arc::clone(&self.rejection_mapper),
        }
    }
}

impl<L: Limiter, K, R> fmt::Debug for RateLimitLayer<L, K, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitLayer")
            .field("limiter_type", &type_name::<L>())
            .field("limiter", &Redacted)
            .field("policy", &self.policy)
            .field("key_extractor", &Redacted)
            .field("rejection_mapper", &Redacted)
            .finish()
    }
}

impl<S, L: Limiter, K, R> Layer<S> for RateLimitLayer<L, K, R> {
    type Service = RateLimitService<S, L, K, R>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: Arc::clone(&self.limiter),
            policy: Arc::clone(&self.policy),
            key_extractor: Arc::clone(&self.key_extractor),
            rejection_mapper: Arc::clone(&self.rejection_mapper),
        }
    }
}

/// The service produced by [`RateLimitLayer`].
pub struct RateLimitService<S, L: Limiter, K, R> {
    inner: S,
    limiter: Arc<L>,
    policy: Arc<L::Policy>,
    key_extractor: Arc<K>,
    rejection_mapper: Arc<R>,
}

impl<S: Clone, L: Limiter, K, R> Clone for RateLimitService<S, L, K, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            limiter: Arc::clone(&self.limiter),
            policy: Arc::clone(&self.policy),
            key_extractor: Arc::clone(&self.key_extractor),
            rejection_mapper: Arc::clone(&self.rejection_mapper),
        }
    }
}

impl<S, L: Limiter, K, R> fmt::Debug for RateLimitService<S, L, K, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitService")
            .field("inner_type", &type_name::<S>())
            .field("inner", &Redacted)
            .field("limiter_type", &type_name::<L>())
            .field("limiter", &Redacted)
            .field("policy", &self.policy)
            .field("key_extractor", &Redacted)
            .field("rejection_mapper", &Redacted)
            .finish()
    }
}

/// The boxed, sendable response future returned by [`RateLimitService`].
pub struct ResponseFuture<F> {
    inner: Pin<Box<dyn Future<Output = F> + Send + 'static>>,
}

impl<F> Future for ResponseFuture<F> {
    type Output = F;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(context)
    }
}

impl<F> fmt::Debug for ResponseFuture<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseFuture")
            .field("state", &Redacted)
            .field("_output", &PhantomData::<fn() -> F>)
            .finish()
    }
}

impl<S, L, K, R, B> Service<Request<B>> for RateLimitService<S, L, K, R>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    L: Limiter + 'static,
    L::Policy: 'static,
    K: ExtractSubjectKey<L::Policy, B> + 'static,
    K::Error: Send + 'static,
    R: Fn(RateLimitRejection<K::Error, L::Error>) -> Response + Send + Sync + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = ResponseFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let subject = self
            .key_extractor
            .extract_subject_key(&request, self.policy.as_ref());

        let limiter = Arc::clone(&self.limiter);
        let policy = Arc::clone(&self.policy);
        let rejection_mapper = Arc::clone(&self.rejection_mapper);

        let inner_clone = self.inner.clone();
        let mut ready_inner = mem::replace(&mut self.inner, inner_clone);

        ResponseFuture {
            inner: Box::pin(async move {
                let subject = match subject {
                    Ok(subject) => subject,
                    Err(error) => {
                        return Ok(rejection_mapper(RateLimitRejection::Key(error)));
                    }
                };

                let check = Check::new(policy.as_ref(), subject);
                let decision = match limiter.check(&check).await {
                    Ok(decision) => decision,
                    Err(error) => {
                        return Ok(rejection_mapper(RateLimitRejection::Backend(error)));
                    }
                };

                if decision.is_enforced_denial() {
                    return Ok(rejection_mapper(RateLimitRejection::Denied(decision)));
                }

                request.extensions_mut().insert(decision);
                ready_inner.call(request).await
            }),
        }
    }
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}
