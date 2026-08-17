//! Behavioral boundaries for the Axum admission middleware.

use std::{
    convert::Infallible,
    error::Error,
    fmt,
    future::{Future, Ready, ready},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::get,
};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use runlimit_axum::{RateLimitLayer, RateLimitRejection, RejectionKind};
use runlimit_core::{
    BatchDecision, Check, Decision, FixedWindowPolicy, Limiter, PolicyId, QuotaDenial, ScopeId,
    SubjectKey,
};
use tower::{Layer, Service, ServiceExt, service_fn};

#[derive(Clone, Copy)]
enum StubOutcome {
    Decision(Decision),
    BackendError,
}

#[derive(Clone)]
struct StubLimiter {
    calls: Arc<AtomicUsize>,
    subjects: Arc<Mutex<Vec<SubjectKey>>>,
    outcome: StubOutcome,
}

impl StubLimiter {
    fn returning(decision: Decision) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            subjects: Arc::new(Mutex::new(Vec::new())),
            outcome: StubOutcome::Decision(decision),
        }
    }

    fn failing() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            subjects: Arc::new(Mutex::new(Vec::new())),
            outcome: StubOutcome::BackendError,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StubError;

impl fmt::Display for StubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stub backend failure")
    }
}

impl Error for StubError {}

impl Limiter for StubLimiter {
    type Policy = FixedWindowPolicy;
    type Error = StubError;

    fn check(
        &self,
        check: &Check<'_, Self::Policy>,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.subjects.lock().unwrap().push(check.subject());
        ready(match self.outcome {
            StubOutcome::Decision(decision) => Ok(decision),
            StubOutcome::BackendError => Err(StubError),
        })
    }

    fn check_all(
        &self,
        _checks: &[Check<'_, Self::Policy>],
    ) -> impl Future<Output = Result<BatchDecision, Self::Error>> + Send {
        ready(Err(StubError))
    }
}

fn policy() -> FixedWindowPolicy {
    FixedWindowPolicy::new(
        PolicyId::new("auth.login").unwrap(),
        ScopeId::new("client").unwrap(),
        8,
        Duration::from_secs(60),
    )
    .unwrap()
}

fn subject(byte: u8) -> SubjectKey {
    SubjectKey::from_digest([byte; 32])
}

fn response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn layer_composes_with_an_axum_router() {
    let decision = Decision::allowed(8, 7, Duration::from_secs(60));
    let layer = RateLimitLayer::new(
        StubLimiter::returning(decision),
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| Ok::<_, Infallible>(subject(0)),
        |_rejection| response(StatusCode::TOO_MANY_REQUESTS),
    );
    let app = Router::new()
        .route(
            "/",
            get(move |request: Request<Body>| async move {
                assert_eq!(request.extensions().get::<Decision>(), Some(&decision));
                StatusCode::NO_CONTENT
            }),
        )
        .layer(layer);

    let result = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(result.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn allowed_request_proceeds_with_decision_extension() {
    let decision = Decision::allowed(8, 7, Duration::from_secs(60));
    let limiter = StubLimiter::returning(decision);
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let inner_calls_for_service = Arc::clone(&inner_calls);
    let inner = service_fn(move |request: Request<Body>| {
        let inner_calls = Arc::clone(&inner_calls_for_service);
        async move {
            inner_calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(request.extensions().get::<Decision>(), Some(&decision));
            Ok::<_, Infallible>(response(StatusCode::NO_CONTENT))
        }
    });
    let layer = RateLimitLayer::new(
        limiter,
        policy(),
        |_request: &Request<Body>, policy: &FixedWindowPolicy| {
            assert_eq!(policy.id().as_str(), "auth.login");
            Ok::<_, &'static str>(subject(1))
        },
        |_rejection| panic!("an allowed request must not be mapped"),
    );

    let result = layer
        .layer(inner)
        .oneshot(Request::new(Body::empty()))
        .await
        .unwrap();

    assert_eq!(result.status(), StatusCode::NO_CONTENT);
    assert_eq!(inner_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn enforced_denial_is_mapped_and_short_circuits_inner_service() {
    let decision = Decision::denied(QuotaDenial::new(8, Duration::from_secs(17)));
    let limiter = StubLimiter::returning(decision);
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let inner_calls_for_service = Arc::clone(&inner_calls);
    let inner = service_fn(move |_request: Request<Body>| {
        inner_calls_for_service.fetch_add(1, Ordering::Relaxed);
        ready(Ok::<_, Infallible>(response(StatusCode::NO_CONTENT)))
    });
    let layer = RateLimitLayer::new(
        limiter,
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| Ok::<_, Infallible>(subject(2)),
        move |rejection: RateLimitRejection<Infallible, StubError>| {
            assert_eq!(rejection.kind(), RejectionKind::Denied);
            match rejection {
                RateLimitRejection::Denied(mapped) => assert_eq!(mapped, decision),
                _ => panic!("unexpected rejection kind"),
            }
            response(StatusCode::TOO_MANY_REQUESTS)
        },
    );

    let result = layer
        .layer(inner)
        .oneshot(Request::new(Body::empty()))
        .await
        .unwrap();

    assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(inner_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn shadow_denial_proceeds_with_decision_extension() {
    let decision = Decision::shadow_denied(QuotaDenial::new(8, Duration::from_secs(17)));
    let limiter = StubLimiter::returning(decision);
    let inner = service_fn(move |request: Request<Body>| async move {
        assert_eq!(request.extensions().get::<Decision>(), Some(&decision));
        Ok::<_, Infallible>(response(StatusCode::ACCEPTED))
    });
    let layer = RateLimitLayer::new(
        limiter,
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| Ok::<_, Infallible>(subject(3)),
        |_rejection| panic!("shadow quota exhaustion must not be rejected"),
    );

    let result = layer
        .layer(inner)
        .oneshot(Request::new(Body::empty()))
        .await
        .unwrap();

    assert_eq!(result.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn key_and_backend_failures_are_owned_by_the_mapper() {
    let unused_inner = service_fn(|_request: Request<Body>| {
        ready(Ok::<_, Infallible>(response(StatusCode::NO_CONTENT)))
    });
    let limiter = StubLimiter::returning(Decision::allowed(8, 7, Duration::from_secs(60)));
    let calls = Arc::clone(&limiter.calls);
    let key_layer = RateLimitLayer::new(
        limiter,
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| {
            Err::<SubjectKey, _>("missing trusted client address")
        },
        |rejection| match rejection {
            RateLimitRejection::Key("missing trusted client address") => {
                response(StatusCode::BAD_REQUEST)
            }
            _ => panic!("unexpected rejection kind"),
        },
    );

    let key_response = key_layer
        .layer(unused_inner)
        .oneshot(Request::new(Body::empty()))
        .await
        .unwrap();
    assert_eq!(key_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let backend_layer = RateLimitLayer::new(
        StubLimiter::failing(),
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| Ok::<_, Infallible>(subject(4)),
        |rejection| match rejection {
            RateLimitRejection::Backend(StubError) => response(StatusCode::SERVICE_UNAVAILABLE),
            _ => panic!("unexpected rejection kind"),
        },
    );
    let backend_response = backend_layer
        .layer(unused_inner)
        .oneshot(Request::new(Body::empty()))
        .await
        .unwrap();
    assert_eq!(backend_response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn forwarding_headers_have_no_effect_unless_the_extractor_uses_them() {
    let fixed_subject = subject(5);
    let limiter = StubLimiter::returning(Decision::allowed(8, 7, Duration::from_secs(60)));
    let observed_subjects = Arc::clone(&limiter.subjects);
    let ignoring_layer = RateLimitLayer::new(
        limiter,
        policy(),
        move |_request: &Request<Body>, _policy: &FixedWindowPolicy| {
            Ok::<_, Infallible>(fixed_subject)
        },
        |_rejection| panic!("unexpected rejection"),
    );
    let inner = service_fn(|_request: Request<Body>| {
        ready(Ok::<_, Infallible>(response(StatusCode::NO_CONTENT)))
    });

    for forwarded in ["198.51.100.1", "203.0.113.9"] {
        let mut request = Request::new(Body::empty());
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static(forwarded));
        ignoring_layer
            .clone()
            .layer(inner)
            .oneshot(request)
            .await
            .unwrap();
    }
    assert_eq!(
        observed_subjects.lock().unwrap().as_slice(),
        &[fixed_subject, fixed_subject]
    );

    let header_subject = subject(6);
    let limiter = StubLimiter::returning(Decision::allowed(8, 7, Duration::from_secs(60)));
    let observed_subjects = Arc::clone(&limiter.subjects);
    let using_layer = RateLimitLayer::new(
        limiter,
        policy(),
        move |request: &Request<Body>, _policy: &FixedWindowPolicy| {
            assert_eq!(request.headers()["x-forwarded-for"], "192.0.2.8");
            Ok::<_, Infallible>(header_subject)
        },
        |_rejection| panic!("unexpected rejection"),
    );
    let mut request = Request::new(Body::empty());
    request
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("192.0.2.8"));

    using_layer.layer(inner).oneshot(request).await.unwrap();
    assert_eq!(
        observed_subjects.lock().unwrap().as_slice(),
        &[header_subject]
    );
}

#[derive(Clone)]
struct ReadinessService {
    ready: Arc<AtomicBool>,
    ready_polls: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

impl Service<Request<Body>> for ReadinessService {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ready_polls.fetch_add(1, Ordering::Relaxed);
        if self.ready.load(Ordering::Relaxed) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn call(&mut self, _request: Request<Body>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::Relaxed);
        ready(Ok(response(StatusCode::NO_CONTENT)))
    }
}

#[tokio::test]
async fn readiness_is_forwarded_and_the_response_future_is_send() {
    let ready_flag = Arc::new(AtomicBool::new(false));
    let ready_polls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let inner = ReadinessService {
        ready: Arc::clone(&ready_flag),
        ready_polls: Arc::clone(&ready_polls),
        calls: Arc::clone(&calls),
    };
    let layer = RateLimitLayer::new(
        StubLimiter::returning(Decision::allowed(8, 7, Duration::from_secs(60))),
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| Ok::<_, Infallible>(subject(7)),
        |_rejection| panic!("unexpected rejection"),
    );
    let mut service = layer.layer(inner);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(service.poll_ready(&mut context).is_pending());
    ready_flag.store(true, Ordering::Relaxed);
    assert!(matches!(
        service.poll_ready(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(ready_polls.load(Ordering::Relaxed), 2);

    let future = service.call(Request::new(Body::empty()));
    assert_send(&future);
    assert_eq!(future.await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

struct ProbeBody {
    polled: Arc<AtomicBool>,
}

impl HttpBody for ProbeBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polled.store(true, Ordering::Relaxed);
        Poll::Ready(None)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[tokio::test]
async fn rejected_request_body_is_never_polled() {
    let body_polled = Arc::new(AtomicBool::new(false));
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let inner_calls_for_service = Arc::clone(&inner_calls);
    let inner = service_fn(move |_request: Request<ProbeBody>| {
        inner_calls_for_service.fetch_add(1, Ordering::Relaxed);
        ready(Ok::<_, Infallible>(response(StatusCode::NO_CONTENT)))
    });
    let layer = RateLimitLayer::new(
        StubLimiter::returning(Decision::denied(QuotaDenial::new(
            8,
            Duration::from_secs(5),
        ))),
        policy(),
        |_request: &Request<ProbeBody>, _policy: &FixedWindowPolicy| {
            Ok::<_, Infallible>(subject(8))
        },
        |_rejection: RateLimitRejection<Infallible, StubError>| {
            response(StatusCode::TOO_MANY_REQUESTS)
        },
    );
    let request = Request::new(ProbeBody {
        polled: Arc::clone(&body_polled),
    });

    let result = layer.layer(inner).oneshot(request).await.unwrap();

    assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(!body_polled.load(Ordering::Relaxed));
    assert_eq!(inner_calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn caller_can_choose_rejection_response_body() {
    let layer = RateLimitLayer::new(
        StubLimiter::failing(),
        policy(),
        |_request: &Request<Body>, _policy: &FixedWindowPolicy| Ok::<_, Infallible>(subject(9)),
        |_rejection| {
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("application-owned response"))
                .unwrap()
        },
    );
    let inner = service_fn(|_request: Request<Body>| {
        ready(Ok::<_, Infallible>(response(StatusCode::NO_CONTENT)))
    });

    let result = layer
        .layer(inner)
        .oneshot(Request::new(Body::empty()))
        .await
        .unwrap();
    let status = result.status();
    let body = to_bytes(result.into_body(), usize::MAX).await.unwrap();

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, "application-owned response");
}

#[test]
fn debug_output_is_useful_without_formatting_callback_state() {
    let secret = String::from("raw-identity-secret");
    let layer = RateLimitLayer::new(
        StubLimiter::returning(Decision::allowed(8, 7, Duration::from_secs(60))),
        policy(),
        move |_request: &Request<Body>, _policy: &FixedWindowPolicy| {
            let _ = &secret;
            Ok::<_, Infallible>(subject(10))
        },
        |_rejection: RateLimitRejection<Infallible, StubError>| {
            response(StatusCode::TOO_MANY_REQUESTS)
        },
    );

    let debug = format!("{layer:?}");

    assert!(debug.contains("StubLimiter"));
    assert!(debug.contains("auth.login"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("raw-identity-secret"));
}

fn assert_send<T: Send>(_value: &T) {}
