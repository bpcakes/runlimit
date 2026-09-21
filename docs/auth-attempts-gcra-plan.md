# Outcome-aware attempts and durable GCRA

Owner: `runlimit-1u5`. Baseline: `77890cdb9ce116cf5da9bb42b8737c6d762a17b7`.

## 1. Outcome

Applications can use upstream-owned consecutive-failure controls and durable
continuously replenished traffic quotas without implementing limiter SQL.
Delivery requires live PostgreSQL evidence, unchanged existing-consumer smoke,
a clean native Codex review over the original baseline, and a pull request.

## 2. Scope

Add attempt policy, memory and PostgreSQL implementations, opaque receipts,
transaction-scoped completion, and a PostgreSQL GCRA backend. Keep existing
quota APIs, no-refund semantics and published migrations unchanged. Authentication
credentials, audit schemas, HTTP bodies, forwarding trust and production policy
values belong to consumers. Do not add a general refund API or circuit-breaker
state machine.

## 3. Current-state evidence

- Fact: `Limiter` separates single/batch errors; its current typed contract is the
  compatibility baseline. Earlier pins require an independent adapter migration.
- Fact: `runlimit-memory/src/gcra.rs` implements GCRA; PostgreSQL has fixed windows.
- Fact: `CheckTransaction` owns bounded PostgreSQL completion; existing tables
  and advisory-lock derivation are rolling-deployment contracts.
- Integration constraint: Batter exposes an opaque scoped SQL executor, not a
  replaceable native connection. Its owned runner releases output after commit.
- Unknown: final consumer policy values. Keep constructors configurable and
  require consumers to choose them; examples are not production recommendations.

## 4. Decisions and design

### D-01 — Separate attempts from ordinary quota

- Status: accepted
- Context: successful authentication resets consecutive failures, not traffic.
- Choice: new validated policy/subject/receipt/outcome types and new observation
  types, leaving existing exhaustive enums untouched. Escalating delay has an
  explicit cap and quiet period; active reservations have a bounded lease.
- Why: additive semantics without weakening ordinary quota consumption.
- Alternatives: quota refunds and application-owned counter SQL are rejected.
- Revisit when: a concrete consumer demonstrates missing generic semantics.

### D-02 — Owned admission and transaction-scoped finalization

- Status: accepted
- Context: final authentication decisions can depend on application row locks.
- Choice: admit without holding a transaction through expensive verification;
  then claim/fence the receipt in the application transaction before app writes,
  determine a typed application outcome, and complete the attempt in that same
  transaction. Low-level executor APIs explicitly require one transaction;
  Batter owns the protected consumer sequence. Stale receipts cannot mutate newer
  state. Abandonment/expiry must not permit unlimited retries. Audit is not reset.
- Why: retry state and authentication state must commit or roll back together.
- Alternatives: post-commit best-effort reset and pre-verification row locks fail
  atomicity or availability requirements.
- Revisit when: tests expose an unenforceable cross-boundary invariant.

GCRA uses the shared pure evaluator, authoritative database time, hard bounded
storage and atomic multi-key admission. New migration bundles are opt-in and do
not edit existing migrations. Raw identifiers never enter storage/observations.

## 5. Execution graph

### T-01 — Outcome-aware attempts

- Outcome: bounded consecutive-failure state works in memory and PostgreSQL.
- Changes: new attempts modules in core/memory/postgres, exports and new migrations.
- Depends on: none
- Verify: deterministic policy/memory tests and live PostgreSQL concurrent
  admission, expiry, stale completion, rollback, reset and hard-capacity tests.
- Recovery: disable new API adoption; retain new tables without rewriting history.
- Done when: tests prove parity and transaction semantics; no existing API changes.

### T-02 — Durable GCRA

- Outcome: replica-safe replenishing traffic quotas without fixed-window bursts.
- Changes: shared core evaluator, memory delegation, new PostgreSQL backend/tables.
- Depends on: none
- Verify: memory parity, timing boundaries, atomic batch denial, cross-replica
  concurrency, hard capacity, cancellation and maintenance tests.
- Recovery: opt-in backend selection; leave existing fixed-window storage intact.
- Done when: live tests and existing external consumer smoke pass.

T-01 and T-02 run in parallel with separate module ownership; T-01 owns shared
exports/manifests after coordination. The integrator owns plans, commits and PR.

## 6. Verification

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `./scripts/run-external-consumer-smoke.sh`.
Run all ignored PostgreSQL integration targets with
`RUNLIMIT_POSTGRES_TEST_DATABASE_URL` pointing only at a disposable PostgreSQL
database and `--ignored --test-threads=1`. Add named regressions for abandoned,
concurrent and stale attempts, failure/reset atomic rollback, cardinality limits,
GCRA batch atomicity, and unpolled futures. Record actual outcomes below.

## 7. Rollout and recovery

Publish additive migrations and explicit initialization/maintenance guidance;
existing consumers need not install them. Merge/publish is not performed by this
workflow. Push a reviewed branch and open a PR, then integrate its exact SHA in
Batter. Production adoption requires its own policy/load review. Never repair a
failure by editing published migration history or by evicting active state.

## 8. Risks and open decisions

The attempts owner resolves expiry/claim races and timing overflow with tests.
The GCRA owner resolves arithmetic/time-watermark and shard-capacity behavior.
The integrator verifies old consumers and the real Batter transaction seam.
Database uncertainty does not authorize replay. Backend observers expose bounded
dimensions, not raw subjects. No throughput or production readiness claim is made.

## Progress

- [x] Inspected baseline and agreed additive boundaries with Batter.
- [x] T-01 implemented and validated (`runlimit-1u5.1`).
- [x] T-02 implemented and validated (`runlimit-1u5.2`).
- [ ] Full validation, native review and PR delivery.

## Surprises & Discoveries

The final auth decision cannot be fixed before application SQL checks. The
transaction seam therefore needs claim-before-callback and outcome completion,
not only a preselected success/reset operation.

## Decision Log

2026-09-21: separated attempts from quotas and selected transaction-scoped claim
and completion to avoid local consumer orchestration or post-commit cleanup.

## Outcomes & Retrospective

2026-09-21 local validation passed: workspace formatting/tests, all-feature
all-target Clippy with warnings denied, and packaged external-consumer smoke on
Rust 1.94.0. PostgreSQL 18.6 passed 9 attempt, 14 GCRA and 32 existing fixed-window
live cases; two additional GCRA non-database tests passed in the workspace run.
Default-feature live coverage also passed before the final two attempt regression
cases were added; all-feature live coverage includes all nine. Memory attempts
passed seven deterministic cases. Native review and PR delivery remain pending.

The first native review found three implementation defects: cleanup did not
advance the GCRA monotonic clock, lowered attempt capacity did not count retained
high slots, and malformed attempt responses lost storage-invariant classification.
All three received root-cause fixes and regressions. Post-fix validation passed
formatting, workspace tests, all-target/all-feature Clippy, and 15 attempt,
17 GCRA and 32 original fixed-window live cases. Full original-range re-review
and PR delivery remain pending.

The second review found two new defects, not recurrences: a savepoint rollback
could preserve an escaped claim's top-level XID, and memory completion exposed
an unreachable admission-only error. Claiming now transactionally rotates the
private token; rollback invalidates it while releasing a savepoint preserves it.
Memory completion has a dedicated poisoned-state error. Eight memory and
17 live PostgreSQL attempt cases, workspace tests and Clippy pass after these
fixes. GCRA and fixed-window behavior are unchanged. Final review is pending.

Storage reclamation is deliberately backend-specific: memory immediately removes
a successful subject; PostgreSQL retains reset state until bounded quiet-period
cleanup. Both permit an immediate next attempt for that subject and preserve
their configured hard storage ceiling. Capacity timing is not a cross-backend
equivalence claim.
