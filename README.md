# Runlimit

Runlimit is a framework-neutral Rust library for enforcing the same keyed,
anchored fixed-window limits in one process or across PostgreSQL-backed
replicas.

The 0.1 API is intentionally pre-stable. The first production target is
authentication throttling in Identitypro.

## Crates

| Crate | Responsibility |
| --- | --- |
| `runlimit-core` | Validated policies, HMAC-derived subject keys, checks, and structured decisions. |
| `runlimit-memory` | Sharded, hard-bounded process-local storage with bounded cleanup work. |
| `runlimit-postgres` | Replica-safe SQLx/PostgreSQL storage, migrations, and bounded maintenance. |

Choose the backend needed by the application:

```toml
[dependencies]
runlimit-core = "0.1.0"
runlimit-memory = "0.1.0"
# Or, for a shared cross-replica quota:
# runlimit-postgres = "0.1.0"
```

During development from a source checkout, a sibling project can use path
dependencies:

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

use runlimit_core::{BatchDecision, Check, FixedWindowPolicy, KeyHasher, PolicyId, ScopeId};
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

    match limiter.check_all(&checks)? {
        BatchDecision::Allowed(decisions) => {
            assert_eq!(decisions.len(), checks.len());
            println!("request admitted");
        }
        BatchDecision::Denied { index, denial } => match denial.retry_after_seconds() {
            Some(seconds) => {
                println!("check {index} denied; retry after {seconds} seconds");
            }
            None => println!("check {index} denied; retry time unavailable"),
        },
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
  portable bounds ensure every core-valid policy is representable by both
  storage backends.
- Decisions expose durations measured by the backend. Memory durations are
  exact at evaluation time. PostgreSQL measures elapsed evaluation time with
  its authoritative database clock and can conservatively overstate the
  remaining time at the caller by commit and transport latency. Use
  `retry_after_seconds()` for an HTTP `Retry-After` value rounded up to the next
  whole second.

The memory and PostgreSQL backends intentionally implement these same
semantics.

## Subject keys and secret rotation

Applications normalize subjects before passing them to Runlimit. Construct
stored keys with `KeyHasher`, which uses domain-separated HMAC-SHA-256 and
requires a secret of at least 32 bytes. Raw emails, account IDs, session IDs,
and IP addresses should not enter storage, logs, metrics labels, or errors.

Use one stable secret across every replica sharing a backend. Rotating the
secret starts fresh counters because every derived subject key changes. Deploy
a rotation to all replicas together: replicas using old and new secrets at the
same time can each admit traffic against different counters.

## Memory backend behavior

`MemoryStore` is process-local and hard bounded:

- The store defaults to one shard so all of `max_keys` is available regardless
  of key distribution.
- Configuring multiple shards divides `max_keys` into fixed per-shard
  capacities. This increases lock concurrency, but an uneven key distribution
  can fill one shard and deny a new key while other shards still have unused
  capacity.
- Active entries are never evicted to make room for new subjects.
- Each check removes at most the configured number of expired entries from its
  shard. An atomic batch receives that allowance once for each check, on the
  shard targeted by that check.
- A new key that cannot fit in its shard is denied with
  `Denial::StorageCapacity`, optionally including the earliest known retry
  duration.

If application code panics while holding a shard lock, that shard remains
poisoned. Every later operation touching it returns
`MemoryStoreError::PoisonedShard` without resetting its counters. With the
default one-shard configuration, this makes the entire store unavailable.
Keep admissions failed closed, alert operators, and replace the store only as
an explicit recovery action; replacement resets all process-local counters.

Treat every `MemoryStoreError` as an admission failure; it is distinct from a
normal quota denial returned in a `Decision` or `BatchDecision`.

## PostgreSQL backend

Use `runlimit-postgres` when a quota must be shared across replicas or survive
process restarts. `PostgresLimiter` uses PostgreSQL time as its authority,
locks batch keys in deterministic order, and commits an allowed batch in one
transaction. Atomic batches use set-based lock, preflight, and update phases,
so the number of SQL phases stays fixed as the bounded batch size grows.

Runlimit's `pg_advisory_xact_lock(bigint)` protocol uses a database-wide
namespace shared by every application and role connected to that database. An
unrelated session holding the same numeric lock can delay an affected counter
until its operation deadline. Use a trusted or dedicated database boundary, or
ensure unrelated roles cannot execute the advisory-lock functions.

**Version 0.1 is not hard-cardinality-bounded in PostgreSQL.** Arbitrary
unique-key spray can grow the table until those windows expire and maintenance
removes them. A production deployment must:

- keep a hard-bounded `MemoryStore` client gate before body parsing and
  PostgreSQL acquisition;
- schedule `cleanup_expired(maximum_rows)` continuously; and
- monitor table rows, index size, disk use, cleanup throughput, and denials at
  the memory gate.

Distributed database capacity enforcement is a tracked follow-up. Until it is
implemented, do not expose PostgreSQL as the only defense against
attacker-controlled key cardinality.

Before serving traffic, apply the bundled migration with
`PostgresLimiter::migrate()`. In a database where application and library
migrations share SQLx's `_sqlx_migrations` table, every participating migrator
must enable `Migrator::set_ignore_missing(true)` so each one tolerates versions
owned by the others. The exported raw `MIGRATOR` keeps SQLx's strict default
and is suitable only when Runlimit exclusively owns that migration history and
connection. An application that must retain a strict host migrator should
vendor the bundled Runlimit SQL as an application-owned migration and not run
either Runlimit migrator against the shared history.

Periodically call `cleanup_expired(maximum_rows)` to bound maintenance work;
expired rows do not affect correctness before cleanup.

No running database is needed to compile Runlimit or its smoke consumer.
Database integration tests should use a disposable PostgreSQL instance.

Database errors must fail closed. `runlimit_postgres::CheckError` distinguishes
operations that definitely did not consume quota from commit outcomes that may
have consumed it. Inspect `may_have_consumed_quota()` for observability and do
not blindly retry an unknown commit as part of a non-idempotent operation.
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
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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
  ./scripts/prepare-release.sh 0.1.0
```

Review the release metadata and hand-written changelog entry, commit them, push
`master`, and wait for CI to pass on that exact commit. Then publish with:

```sh
./scripts/publish-release.sh 0.1.0
```

The publish script requires local `master` to match `origin/master`. It
publishes `runlimit-core`, waits for crates.io to index it, publishes
`runlimit-memory`, waits again, and finally publishes `runlimit-postgres`.
After every crate is indexed, it creates and pushes the matching `v0.1.0` tag.
If a publish stops partway through, resume explicitly with
`RESUME_RELEASE=1 ./scripts/publish-release.sh 0.1.0`; already-published crate
versions are verified before the script continues.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at
your option.
