# Changelog

All notable changes to this workspace are documented here.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

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
[Unreleased]: https://github.com/bpcakes/runlimit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bpcakes/runlimit/releases/tag/v0.1.0
