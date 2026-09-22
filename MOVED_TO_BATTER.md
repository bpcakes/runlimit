# Runlimit development has moved to Batter

Runlimit is maintained in the [`runlimit/` directory of Batter](https://github.com/bpcakes/batter/tree/master/runlimit).
Use [Batter issues](https://github.com/bpcakes/batter/issues) and
[Batter pull requests](https://github.com/bpcakes/batter/pulls) for new work.
This standalone repository retains its source, tags and historical documentation.

## What moved

[Batter PR #8](https://github.com/bpcakes/batter/pull/8), stacked on
[Batter PR #7](https://github.com/bpcakes/batter/pull/7), imports standalone revision
[`12e035dac504a1d348c2058ee7ade8e61f2e7974`](https://github.com/bpcakes/runlimit/commit/12e035dac504a1d348c2058ee7ade8e61f2e7974).
The five packages retain their names: `runlimit-core`, `runlimit-memory`,
`runlimit-postgres`, `runlimit-http` and `runlimit-axum`. Rust imports continue to
use those crate names. Native policies, storage, migrations and transport helpers
remain in Runlimit. The native crates do not depend on Batter; its optional
facade and `batter-runlimit` adapter provide additional operational composition.

The import preserves that source revision's native runtime behavior, migration
SQL and persisted cross-replica protocols. Moving the repository alone does not
require resetting quota state or rewriting applied migrations. Consumers upgrading
from an older revision or published release must still review the intervening API,
policy and schema changes. See the [current native README](https://github.com/bpcakes/batter/blob/master/runlimit/README.md)
and [import provenance](https://github.com/bpcakes/batter/blob/master/runlimit/IMPORT.md).

## Existing consumers

Existing version-pinned dependencies and immutable Git revisions do not follow
this move automatically. They continue to select their original source. The
Batter workspace packages have publishing disabled; their retained version
numbers do not announce a replacement crates.io release.

Use Cargo Git dependencies pinned to a full Batter commit. Cargo finds the
named packages inside the repository; no sibling checkout or consumer
`[patch]` is required:

```toml
[dependencies]
runlimit-core = { git = "https://github.com/bpcakes/batter.git", rev = "70cc6a05be6857aca6ea2f5f127258e75e673d8c" }
runlimit-memory = { git = "https://github.com/bpcakes/batter.git", rev = "70cc6a05be6857aca6ea2f5f127258e75e673d8c" }
# Optional shared PostgreSQL storage:
# runlimit-postgres = { git = "https://github.com/bpcakes/batter.git", rev = "70cc6a05be6857aca6ea2f5f127258e75e673d8c" }
# Optional typed HTTP response metadata:
# runlimit-http = { git = "https://github.com/bpcakes/batter.git", rev = "70cc6a05be6857aca6ea2f5f127258e75e673d8c" }
# Optional Axum/Tower admission middleware:
# runlimit-axum = { git = "https://github.com/bpcakes/batter.git", rev = "70cc6a05be6857aca6ea2f5f127258e75e673d8c" }
```

This example pins a merged Batter commit containing both native libraries.
When upgrading, choose a reviewed full commit from Batter's `master` containing
the migrations. Pin all related native packages, including Runledger if used,
and any direct Batter dependencies to the same URL and revision. Follow Batter's
[compatibility guidance](https://github.com/bpcakes/batter/blob/master/docs/reference-compatibility.md),
regenerate the application's lockfile with Cargo, and validate its dependency
graph and application tests before deploying an upgrade.

Current build, test, source-consumer and migration instructions live in
[Batter's testing guide](https://github.com/bpcakes/batter/blob/master/docs/testing.md).
The standalone release scripts and instructions retained here describe the
historical repository, not the release policy of the Batter workspace.
