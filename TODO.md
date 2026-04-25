# TODO

Deferred work tracked here so it doesn't get lost between conversations.

## STS App Integration Guide — Full operational chapter

The STS App Integration guide (`docs/integration/`, brainstormed 2026-04-24) intentionally scopes its operational coverage to a single "Refresh and expiry" section: the two refresh axes (workload-identity token, STS credential), recommended refresh timing (80% of TTL), and failure modes at expiry.

A future revision should add a deeper operational chapter covering topics that didn't fit v1 but customers will eventually ask about:

- **Caching strategies** — credential reuse within a process; cache key selection; clearing on rotation/role change.
- **Retry on 401 / `ExpiredToken`** — when to refresh-and-retry vs surface the error; backoff; loop-prevention.
- **Observability** — what to log (token issuer, role ARN, expiry — never the token itself), what metrics to emit (refresh-rate, refresh-latency, AssumeRole error rate by code), what to alert on (refresh failures > N, TTL trending down).
- **Graceful degradation** — IDP brief unreachability handling; serving stale-but-still-valid credentials vs failing fast; circuit-breaker patterns.
- **Multi-replica concerns** — per-pod independent refresh vs shared (sidecar / DaemonSet credential broker); thundering-herd avoidance on synchronized expiry.
- **Clock skew** — rejection windows on `nbf` / `iat` / `exp`; NTP requirements; observed-clock-drift remediation.
- **Token rotation events** — key rotation on the IDP side; JWKS cache invalidation; what FlashBlade does on first signature-validation failure.

**Trigger to pull this in:** when customer questions in real conversations cluster on any of the topics above. Likely candidates: anyone running fbsts-validated workloads at scale on K8s, anyone asking "how do I survive an IDP outage."

**Scope note when picked up:** keep it STS-specific. Generic distributed-systems advice (circuit breakers in general, log aggregation in general) belongs elsewhere — this chapter should connect each operational concern back to a concrete STS / OIDC failure mode.
