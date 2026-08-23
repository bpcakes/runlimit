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

<!-- bv-agent-instructions-v3 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking and [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) (`bv`) for graph-aware triage. Issues are stored in `.beads/` and tracked in git. Current `br` workspaces normally export `.beads/issues.jsonl`; older `bd`/legacy workspaces may use `.beads/beads.jsonl`. `bv` auto-discovers the supported JSONL files, so agents should use `br`/`bv` commands instead of hard-coding a single filename.

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects. Instead of parsing .beads/issues.jsonl / .beads/beads.jsonl directly or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). `br` handles creating, modifying, and closing beads.

**CRITICAL: Use ONLY --robot-* flags. Bare bv launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:
bv --robot-triage --format toon
```

Before claiming, verify current state with `br show <id> --json` or `br ready --json`. `recommendations` can include graph-important blocked or assigned work; only `quick_ref.top_picks` and non-empty `claim_command` fields represent claimable work.

#### Other bv Commands

| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with unblocks lists |
| `--robot-priority` | Priority misalignment detection with confidence |
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |

#### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank scores
```

### br Commands for Issue Management

```bash
br ready --json                       # Show issues ready to work (no blockers)
br list --status=open --json          # All open issues
br show <id> --json                   # Full issue details with dependencies
br create --title="..." --type=task --priority=2 --json
br update <id> --status=in_progress --json
br close <id> --reason="Completed" --json
br close <id1> <id2> --reason="Completed" --json
br sync --flush-only                  # Export DB to JSONL after Beads mutations
```

### Workflow Pattern

1. **Triage**: Run `bv --robot-triage` to find the highest-impact actionable work
2. **Claim**: Use `br update <id> --status=in_progress --json`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id> --reason="Completed" --json`
5. **Sync**: Run `br sync --flush-only` after Beads mutations so the JSONL export is current

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready --json` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Git Policy

`br` never commits or pushes. Follow this repository's own git instructions before staging, committing, or pushing. If the repository says "commit only when asked," that rule overrides any generic workflow advice.

<!-- end-bv-agent-instructions -->
