# Runlimit

Runlimit is a framework-neutral Rust library for keyed rate limiting. It
provides anchored fixed windows in memory or across PostgreSQL-backed replicas,
plus a hard-bounded process-local GCRA backend for continuously replenished
quotas.

The 0.x API is intentionally pre-stable. Its application boundary is exercised
by Identitypro authentication throttling.

## Crates

| Crate | Responsibility |
| --- | --- |
| `runlimit-axum` | Caller-controlled Axum/Tower admission middleware. |
| `runlimit-core` | Validated policies, HMAC-derived subject keys, checks, and structured decisions. |
| `runlimit-http` | Framework-neutral IETF draft RateLimit response-field encoding. |
| `runlimit-memory` | Sharded, hard-bounded process-local storage with bounded cleanup work. |
| `runlimit-postgres` | Replica-safe SQLx/PostgreSQL storage, migrations, and bounded maintenance. |

The latest published release is `0.2.0`. Choose the backend needed by the
application:

```toml
[dependencies]
runlimit-core = "0.2.0"
runlimit-memory = "0.2.0"
# Optional Axum/Tower admission middleware:
# runlimit-axum = "0.2.0"
# Optional typed HTTP response metadata:
# runlimit-http = "0.2.0"
# Or, for a shared cross-replica quota:
# runlimit-postgres = "0.2.0"
```

The examples below target the current, unreleased `0.3.0` API. During
development from a source checkout, a sibling project can use path
dependencies to compile them:

```toml
[dependencies]
runlimit-core = { path = "../runlimit/crates/runlimit-core" }
runlimit-memory = { path = "../runlimit/crates/runlimit-memory" }
```

Use a pinned Git revision instead when builds do not share a filesystem.

## Memory backend example

The following admission checks a client and a normalized identity atomically.
If either quota is unavailable, neither counter is consumed.

```rust
use std::{env, error::Error, time::Duration};

use runlimit_core::{
    BatchDecisionView, Check, FixedWindowPolicy, KeyHasher, PolicyId, ScopeId,
};
use runlimit_memory::{MemoryStore, MemoryStoreConfig};

fn main() -> Result<(), Box<dyn Error>> {
    let client_policy = FixedWindowPolicy::new(
        PolicyId::new("auth.login")?,
        ScopeId::new("client")?,
        40,
        Duration::from_secs(60),
    )?;
    let identity_policy = FixedWindowPolicy::new(
        PolicyId::new("auth.login")?,
        ScopeId::new("identity")?,
        8,
        Duration::from_secs(60),
    )?;

    // Load one stable, random secret (at least 32 bytes) from secret storage.
    let secret = env::var("RUNLIMIT_KEY_SECRET")?;
    let key_hasher = KeyHasher::new(secret.as_bytes())?;

    // Address extraction and subject normalization remain application-owned.
    let client = key_hasher.hash_for(&client_policy, b"client-network:192.0.2.4");
    let identity = key_hasher.hash_for(&identity_policy, b"user@example.test");

    let config = MemoryStoreConfig::new(50_000)?.with_shard_count(64)?;
    let limiter = MemoryStore::new(config);
    let checks = [
        Check::new(&client_policy, client),
        Check::new(&identity_policy, identity),
    ];

    let decision = limiter.check_all(&checks)?;
    match decision.view() {
        BatchDecisionView::Allowed { decisions } => {
            assert_eq!(decisions.len(), checks.len());
            println!("request admitted");
        }
        BatchDecisionView::Denied { index, denial } => match denial.retry_after_seconds() {
            Some(seconds) => {
                println!("check {index} denied; retry after {seconds} seconds");
            }
            None => println!("check {index} denied; retry time unavailable"),
        },
        BatchDecisionView::ShadowDenied { index, .. } => {
            println!("request admitted after check {index} was shadow denied");
        }
    }

    Ok(())
}
```

A compile-checked copy lives in `smoke/external-consumer`. Check it as an
independent consumer with:

```sh
cargo check \
  --manifest-path smoke/external-consumer/Cargo.toml \
  --locked \
  --target-dir target/external-consumer
```

## Generic backend API

Async application adapters can be generic over `runlimit_core::Limiter` and
swap storage backends without depending on an async-runtime abstraction:

```rust
use runlimit_core::{BatchDecision, Check, Limiter};

async fn admit<L: Limiter>(
    limiter: &L,
    checks: &[Check<'_, L::Policy>],
) -> Result<BatchDecision, L::Error> {
    limiter.check_all(checks).await
}
```

`Limiter` uses static dispatch with no required future boxing and returns
`Send` futures. It is intentionally not object-safe; use a generic parameter
for test-time backend substitution, or implement `Limiter` on an
application-owned enum for runtime selection.

The inherent `MemoryStore::check` and `MemoryStore::check_all` APIs remain
synchronous. In generic code the trait methods are selected automatically. To
request the async trait method from a concrete memory store, use a fully
qualified call such as `Limiter::check(&store, &check).await`.

## Axum admission middleware

`runlimit-axum` provides `RateLimitLayer` for checks that must run before an
Axum handler or request-body extractor. The application supplies a synchronous
key extractor and a rejection mapper. The key extractor receives the request
and policy, while the mapper owns the status, body, and headers for missing
trusted metadata, enforced denials, and backend failures.

The adapter does not interpret `Forwarded`, `X-Forwarded-For`, `ConnectInfo`,
cookies, or application identities. Establish trust and normalize identities
at the application boundary, then return an opaque `SubjectKey`. Allowed and
shadow-denied decisions are inserted into request extensions for downstream
handlers. Enforced quota and capacity denials short-circuit before the inner
service is called or the request body is consumed.

## HTTP response metadata

`runlimit-http` encodes caller-selected policy and decision metadata using the
versioned `draft_11` module. The active Internet-Draft uses the Structured
Field values `RateLimit-Policy: "name";q=N;w=S` and
`RateLimit: "name";r=N;t=S`.

The helpers return typed HTTP header names and values. They do not select a
response status or body, emit `Retry-After`, expose partition keys, or decide
which policies an application should disclose. Policy periods advertised in
`RateLimit-Policy` must be exact whole seconds; dynamic service durations are
rounded up. Encoding also rejects quota values outside RFC 9651's Structured
Field integer range.

## Optional Serde support

The core and storage backend crates have an opt-in `serde` feature. Enabling it
on a backend also enables it for `runlimit-core`:

```toml
[dependencies]
runlimit-memory = { version = "0.2.0", features = ["serde"] }
```

The feature serializes validated policy and scope identifiers as strings;
fixed-window and GCRA policies without their derived fingerprints; quota mode;
tagged `Decision`/`Denial`/`BatchDecision` values; and backend configuration
values. `MemoryStoreStats` is also serializable for telemetry. Durations retain
their exact seconds and nanoseconds. Deserialization rejects unknown fields
and values that violate Runlimit's constructors or decision invariants.

`SubjectKey`, `CounterKey`, `PolicyFingerprint`, `KeyHasher`, and live backend
instances deliberately do not implement Serde traits. Keep opaque storage keys
and hashing secrets out of generic configuration and telemetry paths.

## Fixed-window semantics

Runlimit implements **anchored** fixed windows. The first allowed check for a
storage key starts its window; subsequent checks use that anchor until the
entire duration elapses. Windows are not aligned to wall-clock boundaries such
as calendar minutes.

- Denied checks do not consume quota.
- A batch is all-or-nothing and allowed decisions retain input order.
- Duplicate storage keys in a batch are rejected as caller errors.
- The policy identifier, scope, limit, and window are fingerprinted into the
  storage key. Changing any of them starts an independent counter instead of
  reinterpreting existing state.
- Core accepts limits through `runlimit_core::MAX_LIMIT` and exact
  whole-millisecond windows through `runlimit_core::MAX_WINDOW`. These shared
  portable bounds ensure every core-valid fixed-window policy is representable
  by both fixed-window storage backends.
- Decisions expose durations measured by the backend. Memory durations are
  exact at evaluation time. PostgreSQL measures elapsed evaluation time with
  its authoritative database clock and can conservatively overstate the
  remaining time at the caller by commit and transport latency. Use
  `retry_after_seconds()` for an HTTP `Retry-After` value rounded up to the next
  whole second.

The memory and PostgreSQL backends intentionally implement these same
semantics.

## GCRA semantics

`GcraPolicy` and `GcraStore` provide a continuously replenished quota without
fixed-window boundary bursts:

```rust
use std::time::Duration;

use runlimit_core::{Check, GcraPolicy, PolicyId, ScopeId, SubjectKey};
use runlimit_memory::{GcraStore, MemoryStoreConfig};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let policy = GcraPolicy::new(
    PolicyId::new("api.read")?,
    ScopeId::new("client")?,
    10,                       // units replenished
    Duration::from_secs(1),   // during this period
    20,                       // maximum immediate burst
)?;
let limiter = GcraStore::new(MemoryStoreConfig::new(50_000)?);
let decision = limiter.check(&Check::new(
    &policy,
    SubjectKey::from_digest([7; 32]),
))?;
assert!(decision.permits_request());
# Ok(())
# }
```

The backend uses exact scaled-integer arithmetic rather than a floating-point
token count. Policy periods must be exact whole milliseconds; reported retry
and full-replenishment durations round up to the next whole millisecond.
`quota`, `period`, and `burst_capacity` are all part of the policy fingerprint.
Each key uses constant-size state, and it becomes eligible for bounded cleanup
once its full burst capacity has replenished.

`GcraStore` is process-local. `PostgresLimiter` supports fixed-window policies
only.

## Shadow mode

Use `with_quota_mode(QuotaMode::Shadow)` to warm and observe a policy before
enforcing it. Quota exhaustion then returns a shadow-denied decision for which
`permits_request()` is true and `would_deny()` is also true. A shadow denial
does not consume quota. Storage-capacity denials and backend errors always
remain fail-closed.

Quota mode is deliberately excluded from the policy fingerprint, so switching
a warmed policy to enforcement keeps its counter state. Atomic batches reject
mixed enforcement and shadow modes; a denied or shadow-denied batch consumes
nothing.

## Operational observations

`MemoryStore`, `GcraStore`, and `PostgresLimiter` accept an optional
`runlimit_core::Observer`. Admission observations classify outcome, quota
consumption certainty, and elapsed time; cleanup observations report bounded
work. The memory stores also report per-shard capacity headroom. Observations
intentionally omit subject keys, backend error text, and other sensitive
high-cardinality values. When relevant to a single check, admission observations
include the policy fingerprint alongside its policy and scope identifiers.

Callbacks run synchronously after memory locks are released or database
transactions are finalized. Keep them fast and hand expensive export work to
another thread. Runlimit catches observer panics so telemetry cannot change an
admission result. PostgreSQL observations preserve the distinction between
definite non-consumption and a commit result that may already have consumed
quota.

## Subject keys and secret rotation

Applications normalize subjects before passing them to Runlimit. Construct
stored keys with `KeyHasher`, which uses domain-separated HMAC-SHA-256 and
requires a secret of at least 32 bytes. Raw emails, account IDs, session IDs,
and IP addresses should not enter storage, logs, metrics labels, or errors.
`KeyHasher` precomputes key-equivalent HMAC state instead of retaining the raw
secret or rebuilding the key schedule for every subject. Treat a live hasher
and its clones as secret material; their debug output is redacted and their
underlying SHA-256 state and buffered input are wiped when dropped.

Use one stable secret across every replica sharing a backend. Rotating the
secret starts fresh counters because every derived subject key changes. Deploy
a rotation to all replicas together: replicas using old and new secrets at the
same time can each admit traffic against different counters.

## Memory backend behavior

`MemoryStore` and `GcraStore` are process-local and hard bounded:

- The store defaults to one shard so all of `max_keys` is available regardless
  of key distribution.
- Configuring multiple shards divides `max_keys` into fixed per-shard
  capacities. This increases lock concurrency, but an uneven key distribution
  can fill one shard and deny a new key while other shards still have unused
  capacity.
- Active entries are never evicted to make room for new subjects.
- Each check removes at most the configured number of expired entries from its
  shard. An atomic batch receives that allowance once for each check on the
  shard targeted by that check. A fixed-window entry expires at its anchored
  deadline; a GCRA entry expires when its full capacity has replenished.
- An atomic batch targeting more distinct keys at one shard than that shard can
  ever hold returns
  `MemoryStoreError::BatchExceedsShardCapacity { shard_index, key_count,
  capacity }`. This is a structural error: waiting for expiry cannot make the
  batch fit.
- A new key that cannot fit in its shard is denied with
  `Denial::storage_capacity`, optionally including the earliest known retry
  duration when the same operation may fit after existing entries expire.

If application code panics while holding a shard lock, that shard remains
poisoned. Every later operation touching it returns
`MemoryStoreError::PoisonedShard` without resetting its counters. With the
default one-shard configuration, this makes the entire store unavailable.
Keep admissions failed closed and alert operators. As an explicit availability
tradeoff, `recover_poisoned()` on either store atomically empties only poisoned
shards, clears their poison flags, preserves healthy-shard counters, and
returns the number recovered. Resetting those counters can admit requests that
their lost state would have denied; replacing the store is a broader reset
with the same security consequence for every shard.

Treat every `MemoryStoreError` as an admission failure; it is distinct from a
normal quota denial returned in a `Decision` or `BatchDecision`.

## PostgreSQL backend

Use `runlimit-postgres` when a quota must be shared across replicas or survive
process restarts. `PostgresLimiter` uses PostgreSQL time as its authority,
locks batch keys in deterministic order, and commits an allowed batch in one
transaction. Atomic batches use set-based lock, preflight, and update phases,
so the number of SQL phases stays fixed as the bounded batch size grows.
Authoritative time calls are explicitly resolved as
`pg_catalog.clock_timestamp()`, so a caller-controlled `search_path` cannot
substitute another clock function.

`PostgresConfig::pool_acquire_timeout` bounds waiting for a pooled connection.
After acquisition, the check or cleanup receives a fresh
`operation_timeout` budget for transaction begin, statements, lock waits,
rollback, and commit. If an application also imposes an outer timeout, allow
for both configured budgets plus scheduling overhead; cancelling around commit
can leave its outcome unknown.

Runlimit's `pg_advisory_xact_lock(bigint)` protocol uses a database-wide
namespace shared by every application and role connected to that database. An
unrelated session holding the same numeric lock can delay an affected counter
until its operation deadline. Use a trusted or dedicated database boundary, or
ensure unrelated roles cannot execute the advisory-lock functions.

Version 0.2 hard-bounds PostgreSQL cardinality with 256 persistent capacity
shards. `PostgresConfig::maximum_rows_per_shard` defaults to 4,096 and can be
lowered or raised through the database-enforced maximum of 65,536. Admission
locks the affected ledger shards and reserves all missing batch keys in the
same transaction as quota consumption. A full shard denies new keys with
`Denial::storage_capacity`; existing keys remain usable and active rows are
never evicted. The migration's trigger-maintained ledger also caps inserts
from older replicas at 65,536 rows per shard during a rolling deployment.

The bound is per shard, so skew can deny a new key while other shards retain
headroom. Expiry does not itself release a ledger slot:
`cleanup_expired(maximum_rows)` must delete the row before its capacity becomes
reusable. Keep scheduling bounded cleanup and monitor shard headroom, table and
index size, cleanup throughput, and storage-capacity denials. A coarse
hard-bounded memory gate is still recommended before body parsing and
PostgreSQL acquisition to protect application and pool capacity.

Before serving traffic, apply the bundled migrations with
`PostgresLimiter::migrate()`. In a database where application and library
migrations share SQLx's `_sqlx_migrations` table, every participating migrator
must enable `Migrator::set_ignore_missing(true)` so each one tolerates versions
owned by the others. The exported raw `MIGRATOR` keeps SQLx's strict default
and is suitable only when Runlimit exclusively owns that migration history and
connection. An application that must retain a strict host migrator should
vendor the bundled Runlimit SQL as application-owned migrations and not run
either Runlimit migrator against the shared history. The exact bundled
statements are available as `CREATE_RUNLIMIT_FIXED_WINDOWS_SQL`,
`SET_RUNLIMIT_FIXED_WINDOWS_FILLFACTOR_SQL`, and
`BOUND_RUNLIMIT_FIXED_WINDOW_CARDINALITY_SQL` so hosts can vendor them without
reaching into crate source files.

Periodically call `cleanup_expired(maximum_rows)` to bound maintenance work;
expired rows do not affect correctness before cleanup. The cleanup query
materializes one PostgreSQL clock sample so the expiry predicate remains an
index range condition; when no rows are expired it does not filter a full scan
of active windows.

The counter table is update-heavy. Each admission after a counter row's initial
insert updates that row and leaves a dead heap tuple. In-window increments of
`used` can use PostgreSQL HOT updates, but starting a new anchored window also
changes the indexed `window_expires_at` value, so window renewals cannot be HOT
and also leave dead index entries. Deleting expired rows adds more dead tuples.
One bundled additive migration sets the table `fillfactor` to 80, reserving
page space for HOT counter updates at the cost of a larger live heap; it does
not remove the need for autovacuum. It remains separate from 0.1.0's
create-table migration so existing SQLx histories retain the published
checksum. The following additive migration installs the capacity ledger,
generated shard column, and statement-level maintenance triggers without
changing that published migration.

Tune autovacuum for churn rather than accepting its table-wide defaults
unchanged. The following is a reasonable starting point, not a capacity
guarantee:

```sql
ALTER TABLE runlimit_fixed_windows SET (
    autovacuum_vacuum_threshold = 500,
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_threshold = 500,
    autovacuum_analyze_scale_factor = 0.02
);
```

PostgreSQL schedules vacuum after approximately the threshold plus the scale
factor times the estimated live rows. Lower the values for a large or
high-throughput counter table, and ensure the cluster's autovacuum workers and
cost limits can keep up. Monitor the live/dead tuple estimates, HOT-update
ratio, vacuum cadence, and heap/index bytes together:

```sql
SELECT
    n_live_tup,
    n_dead_tup,
    n_tup_upd,
    n_tup_hot_upd,
    last_autovacuum,
    autovacuum_count,
    pg_size_pretty(pg_relation_size(relid)) AS heap_size,
    pg_size_pretty(pg_indexes_size(relid)) AS index_size
FROM pg_stat_user_tables
WHERE relid = 'runlimit_fixed_windows'::regclass;
```

Alert when dead tuples or relation bytes keep rising across completed
autovacuums while live cardinality is stable. Check for long-running
transactions that prevent tuple removal before adding more vacuum capacity.
Ordinary vacuum makes dead space reusable but does not return relation files to
the operating system. The fillfactor migration likewise does not rewrite pages
created by 0.1.0; if an existing table or expiry index already needs repacking,
plan `REINDEX INDEX CONCURRENTLY` for a confirmed bloated index or an online
table repack. Use locking `VACUUM FULL` only in a separate maintenance window.

No running database is needed to compile Runlimit or its smoke consumer.
Database integration tests should use a disposable PostgreSQL instance.

Database errors must fail closed. `runlimit_postgres::CheckError` distinguishes
operations that definitely did not consume quota from commit outcomes that may
have consumed it. Inspect `may_have_consumed_quota()` for observability and do
not blindly retry an unknown commit as part of a non-idempotent operation.
When a read-only denial has already been produced, a rollback failure does not
replace it with an error; Runlimit returns the denial and discards that
connection.
`MaintenanceError` makes the corresponding distinction for cleanup; inspect
`may_have_removed_rows()` before deciding whether an unconfirmed cleanup needs
to be retried.

## Production topology

The memory backend enforces a per-process quota, not a fleet-wide quota. In a
multi-replica service, use PostgreSQL for authoritative shared identity,
account, or global limits, while retaining a coarse hard-bounded memory policy
as the first-line client/cardinality gate. Give the two gates distinct policy
identifiers: the local gate protects parsing and database capacity, while the
PostgreSQL policy enforces the shared quota.

All replicas sharing PostgreSQL must use the same policies, normalization rules,
and HMAC secret. Readiness checks should verify the dependencies required by
the chosen fail-closed path.

## Application-owned boundaries

Runlimit owns counter mechanics and storage. Applications continue to own:

- trusted-proxy configuration and client-address extraction;
- IPv4/IPv6 aggregation and identity normalization;
- route policy selection and HTTP/gRPC response formats;
- concurrency bulkheads such as Tokio semaphores;
- durable password lockouts, resend cooldowns, and business quotas.

In particular, Runlimit does not inspect forwarding headers. Only the
application knows which network peers are trusted to supply them. Concurrency
limits also remain separate because they bound simultaneous work rather than
work admitted during a time window.

## Development

The minimum supported Rust version is 1.88. Before handing off changes, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check \
  --manifest-path smoke/external-consumer/Cargo.toml \
  --locked \
  --target-dir target/external-consumer
```

Remaining work toward a stable release is tracked in `ROADMAP.md`.

## Releasing

Prepare a release from a clean checkout:

```sh
RUNLIMIT_POSTGRES_TEST_DATABASE_URL=postgresql://... \
  ./scripts/prepare-release.sh X.Y.Z
```

Review the release metadata and hand-written changelog entry, commit them, push
`master`, and wait for CI to pass on that exact commit. Then publish with:

```sh
./scripts/publish-release.sh X.Y.Z
```

The publish script requires local `master` to match `origin/master`. In
dependency order it publishes `runlimit-core`, `runlimit-memory`,
`runlimit-postgres`, `runlimit-http`, and `runlimit-axum`, waiting for crates.io
to index each one before continuing. After every crate is indexed, it creates
and pushes the matching `vX.Y.Z` tag. If a publish stops partway through,
resume explicitly with
`RESUME_RELEASE=1 ./scripts/publish-release.sh X.Y.Z`; already-published crate
versions are verified before the script continues.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at
your option.
