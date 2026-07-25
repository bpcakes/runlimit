# Runlimit roadmap

The 0.1 workspace establishes the shared fixed-window contract and its first
two storage backends. Before publishing a stable release:

1. [ ] Integrate `runlimit-core` and `runlimit-memory` into Identitypro and
   adjust the consumer-facing API from that experience.
2. [ ] Add replica-safe, fail-closed PostgreSQL cardinality enforcement. Until
   then, require a hard-bounded local gate ahead of PostgreSQL and continuous
   expired-row cleanup.
3. [ ] Decide whether low-level `Decision` constructors should become
   validated or private backend SPI.
4. [x] Define shared portable upper bounds for limits and window durations,
   rejecting nonportable policies in core and preserving exact memory and
   PostgreSQL time arithmetic at the boundary.
5. [ ] Build optional Axum and Tonic adapters over the shared `Limiter` trait
   without moving proxy trust, subject normalization, or response-body policy
   into Runlimit.
6. [ ] Evaluate an optional GCRA/token-bucket backend for non-authentication
   use cases without changing fixed-window semantics.
