# Changelog

All notable changes to this workspace are documented here.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Added

- Add borrowed `DecisionView` and `BatchDecisionView` enums so callers can
  exhaustively match valid decision states without reconstructing them from
  optional accessors. Existing accessors and Serde representations remain
  unchanged.

### Changed

- **Breaking:** replace the raw seven-field `AdmissionObservation::new`
  constructor with semantic failed-check and failed-batch factories. Policy ID
  scope, and configuration-fingerprint metadata are now derived together from
  a validated check, while failure factories require an explicit consumption
  status. The existing `Debug` field representation remains unchanged.
- **Breaking:** replace the raw `CleanupObservation::new` constructor with
  `confirmed`, `definitely_no_effect`, and `outcome_unknown` factories so a
  confirmed removal count cannot be paired with contradictory consumption
  certainty. Existing getters and the `Debug` field representation remain
  unchanged.
- **Breaking:** replace directly constructible decision and denial enum states
  with validated constructors and read-only accessors. Shadow denials now
  require `QuotaDenial`, allowed batches reject denied members, and the Serde
  wire representation remains unchanged.
- **Breaking:** remove `From<PolicyError> for GcraPolicyError`, whose public
  conversion could panic for constructible fixed-window limit errors. Policy
  constructors continue to report the same algorithm-specific validation
  errors in the same order.

## [0.2.1] - 2026-08-08

### Added

- Add `AdmissionObservation::from_check` and
  `AdmissionObservation::from_batch` constructors for consistently deriving
  backend-neutral outcome, consumption, and relevant-policy metadata from
  completed admission decisions.

### Changed

- Share the bounded shard, expiration, capacity, locking, and recovery
  machinery used by the in-memory fixed-window and GCRA stores while retaining
  their separate policy algorithms and existing behavior.
- Reorganize the PostgreSQL backend into focused configuration, error,
  protocol, admission, and maintenance modules without changing its public
  paths, SQL protocol, or published migrations.

## [0.2.0] - 2026-07-25

### Added

- Add a generic async `Limiter` trait with an associated policy type for
  statically dispatched storage and adapter substitution.
- Add `GcraPolicy` and a hard-bounded process-local `GcraStore` with exact
  scaled-integer replenishment, weighted checks, atomic batches, and bounded
  cleanup.
- Add per-policy enforce and shadow modes. Shadow quota denials are explicit,
  permit the application request, and retain warmed counter state for a later
  switch to enforcement.
- Add backend-neutral operational observers for admission outcome, consumption
  certainty, latency, cleanup work, and capacity headroom.
- Add `runlimit-axum`, caller-controlled Axum/Tower middleware that checks
  admission before the inner service without interpreting forwarding headers
  or defining application responses.
- Add `runlimit-http` with versioned helpers for the active IETF
  `RateLimit-Policy` and `RateLimit` draft-11 response fields.
- Add replica-safe PostgreSQL cardinality enforcement with 256 stable capacity
  shards, a transactionally maintained ledger, a configurable lower
  operational bound, and a database-enforced rolling-deployment ceiling.
- Add opt-in, invariant-preserving Serde support for public policy, decision,
  backend configuration, and memory telemetry value types.
- Add `Debug` for `MemoryStore`, `Clone` for `KeyHasher`, explicit poisoned
  shard recovery, and public constants for each bundled PostgreSQL migration.

### Changed

- Generalize checks over `RateLimitPolicy`, and rename algorithm-neutral
  decision metadata from limit/remaining/reset to
  capacity/available/replenishes-after.
- Precompute `KeyHasher`'s zeroizing HMAC state so each subject derivation
  avoids rebuilding the SHA-256 key schedule.
- Use already-uniform counter-key material directly for memory shard selection
  and entry hashing, and make quota arithmetic fail closed if stored usage ever
  exceeds its invariant.
- Resolve PostgreSQL's authoritative clock explicitly through `pg_catalog` and
  give pool acquisition a separate timeout so a connection survivor receives
  a fresh database-operation budget.
- Mark PostgreSQL `CheckError`, `MaintenanceError`, `PostgresConfigError`, and
  core `BatchDecision` as non-exhaustive so 0.x releases can add variants
  without breaking consumers.
- Reject in-memory atomic batches that can never fit in a target shard with a
  structural `MemoryStoreError` instead of a retryable capacity denial.
- Route PostgreSQL single and batch admission through the same deterministic
  logical-key, counter-row, and capacity-shard lock protocol, and configure
  transaction-local timeouts once after `BEGIN`.
- Reserve heap space for HOT counter updates with an additive PostgreSQL
  `fillfactor` migration and document workload-specific autovacuum monitoring
  and tuning.

### Fixed

- Preserve a valid PostgreSQL denial when rollback confirmation fails or its
  client deadline expires; the affected connection is discarded.
- Sample PostgreSQL cleanup time once in a materialized CTE so the expiry
  predicate remains an index range condition and bounded cleanup does not scan
  every active row.

## [0.1.0] - 2026-07-24

### Added

- Add framework-neutral fixed-window policies, opaque HMAC-derived subject
  keys, structured decisions, and all-or-nothing ordered batch checks.
- Add a hard-bounded, sharded in-memory backend with bounded cleanup work and
  fail-closed capacity exhaustion.
- Add a replica-safe SQLx/PostgreSQL backend with database-authoritative time,
  transactional batch admission, bundled migrations, and bounded expired-row
  cleanup.
- Add Rust 1.88 compatibility checks, disposable PostgreSQL integration tests,
  and an external-consumer smoke test for packaged crates.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/bpcakes/runlimit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/bpcakes/runlimit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bpcakes/runlimit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bpcakes/runlimit/releases/tag/v0.1.0
