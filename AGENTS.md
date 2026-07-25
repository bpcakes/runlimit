# Runlimit contributor guide

Runlimit is a framework-neutral rate-limiting library. Keep application policy
at the application boundary and keep backend behavior aligned.

Runlimit is pre-1.0, so public Rust and wire APIs may make deliberate
semver-signaled hard cuts. Published migrations and persistent cross-replica
protocols are immutable; preserve their compatibility through rolling
deployments.

## Architecture

- `runlimit-core` owns validated policy identifiers, fixed-window and GCRA
  policy configuration, opaque subject keys, key derivation, and structured
  decisions. It must not depend on an async runtime, HTTP framework, or
  database driver.
- `runlimit-memory` owns process-local storage. Its cardinality must be hard
  bounded, cleanup work per check must be bounded, and capacity exhaustion must
  fail closed without evicting active entries.
- `runlimit-postgres` owns replica-safe SQLx persistence and bundled migrations.
  It uses PostgreSQL time as the authority and must state whether a failed
  operation may already have consumed quota. Its advisory-lock derivation is a
  cross-replica protocol and must remain stable through rolling deployments.
- HTTP/gRPC adapters must not decide which forwarding headers are trusted,
  normalize application identities, or define application response bodies.

## Semantic invariants

- The memory fixed-window and PostgreSQL backends implement the same anchored
  fixed-window semantics. `GcraStore` implements only `GcraPolicy`.
- A policy configuration fingerprint is part of every storage key. Changing
  any storage-relevant configuration never reinterprets an existing counter.
- Enforced and shadow-denied checks do not consume quota. Storage-capacity
  denials are always enforced.
- Multi-check operations are all-or-nothing and preserve the caller's input
  order in returned decisions.
- Retry durations are measured from the backend's authoritative evaluation
  time and round up when converted to whole-second headers. PostgreSQL measures
  elapsed evaluation time with its database clock and may conservatively
  overstate the duration at the caller by commit and transport latency.
- Raw subjects must not enter storage, logs, or error messages. Applications
  should derive subject keys with a secret of at least 32 bytes.
- PostgreSQL 0.1 storage is not hard-cardinality-bounded. Deploy it behind a
  bounded local gate, schedule expired-row cleanup, and monitor table growth.
- PostgreSQL 0.2 storage is hard-bounded per persistent capacity shard. Keep
  the shard derivation and database ceiling stable, schedule expired-row
  cleanup to reclaim slots, and monitor shard skew and table growth.

## Checks

Run before handing work off:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the required database suite against disposable PostgreSQL with:

```sh
RUNLIMIT_POSTGRES_TEST_DATABASE_URL=postgresql://... \
  cargo test -p runlimit-postgres --test postgres -- --ignored --test-threads=1
```
