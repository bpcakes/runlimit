# Runlimit roadmap

The 0.2 workspace adds a policy-generic adapter boundary, a process-local GCRA
backend, and hard-bounded PostgreSQL storage. Before publishing a stable
release:

1. [x] Integrate `runlimit-core` and `runlimit-memory` into Identitypro and
   adjust the consumer-facing API from that experience.
2. [x] Add replica-safe, fail-closed PostgreSQL cardinality enforcement with
   stable capacity sharding and continuous bounded expired-row cleanup.
3. [x] Make low-level decision and batch construction validated so invalid
   capacities, shadow capacity denials, and denied members in allowed batches
   cannot enter the public response algebra.
4. [x] Define shared portable upper bounds for limits and window durations,
   rejecting nonportable policies in core and preserving exact memory and
   PostgreSQL time arithmetic at the boundary.
5. [x] Build an optional Axum adapter over the shared `Limiter` trait without
   moving proxy trust, subject normalization, or response-body policy into
   Runlimit.
6. [ ] Evaluate a Tonic adapter with the same application-owned trust
   boundary.
7. [x] Add a GCRA backend for continuously replenished quotas without changing
   fixed-window semantics.
8. [x] Add per-policy shadow mode, backend-neutral operational observations,
   and versioned IETF RateLimit response-field helpers.
