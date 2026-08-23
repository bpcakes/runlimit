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

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (open, unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only open, unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->
