//! Framework-neutral contracts shared by Runlimit storage backends.
//!
//! This crate defines anchored fixed-window and GCRA policies, opaque subject
//! keys, checks, and backend-independent decisions. It deliberately contains
//! no async runtime, transport framework, or persistence integration.
//!
//! Applications own subject normalization and policy selection. Raw subjects
//! should be converted to [`SubjectKey`] values with [`KeyHasher`] before they
//! cross into a storage backend.
//! Async application adapters can use [`Limiter`] for generic dispatch across
//! storage backends without requiring boxed futures.
//!
//! The optional `serde` feature provides validated policy and response-metadata
//! wire types. Opaque [`SubjectKey`], [`CounterKey`], and
//! [`PolicyFingerprint`] values intentionally remain non-serializable.

mod batch;
mod check;
mod counter;
mod decision;
mod identifier;
mod key;
mod limiter;
mod observation;
mod policy;

pub use batch::{BatchError, validate_batch};
pub use check::{Check, CheckError};
pub use counter::CounterKey;
pub use decision::{BatchDecision, Decision, DecisionError, Denial, DenialKind, QuotaDenial};
pub use identifier::{IdentifierError, MAX_IDENTIFIER_LENGTH, PolicyId, ScopeId};
pub use key::{KeyHasher, KeyHasherError, SubjectKey};
pub use limiter::Limiter;
pub use observation::{
    AdmissionObservation, AdmissionOperation, AdmissionOutcome, CapacityObservation,
    CleanupObservation, ConsumptionStatus, Observation, Observer, observe_safely,
};
pub use policy::{
    FixedWindowPolicy, GcraPolicy, GcraPolicyError, MAX_LIMIT, MAX_WINDOW, MAX_WINDOW_MILLIS,
    PolicyError, PolicyFingerprint, QuotaMode, RateLimitPolicy,
};
