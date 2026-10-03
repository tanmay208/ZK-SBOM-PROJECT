# API Security Audit

## Confirmed Issues

1. **Unauthenticated high-cost and mutating operations.** SBOM upload, vulnerability ingestion, proof generation, proof verification, and certificate lookup omit authentication. The 10 MB request cap limits individual bodies but there is no rate limiting, concurrency control, queue, or per-principal quota. Classification: CONFIRMED VULNERABILITY; severity High for availability/integrity, exact impact depends on network exposure.
2. **Unfiltered global data access.** Authenticated list routes query entire tables with offset/limit but no user, vendor, or tenant predicate. The limit is honored by the ORM query, so this is not an unbounded single-response query; it is an authorization/BOLA issue. Classification: CONFIRMED VULNERABILITY under RBAC-001.
3. **Verification input is permissive.** `VerifyProofRequest` allows identifier strings matching alphanumeric/underscore or any value beginning with `0x`, rather than requiring fixed-length field encodings. This makes malformed public inputs reachable and allows misleading metadata, although a genuine proof still must verify. Classification: SECURITY WEAKNESS; cryptographic bypass not proven from this alone.
4. **Extra-field handling is inconsistent.** Verification forbids extras and policy forbids extras; SBOM and vulnerability request models do not set `extra="forbid"`, so silently ignored fields are possible. No direct privilege field was found in these models. Classification: HARDENING RECOMMENDATION.
5. **Error metadata exposure.** `ProofJobResponse` includes `error_message`; prover writes subprocess stderr and `str(e)` into it. With unauthenticated job retrieval, internal tool errors and paths may be disclosed. Classification: CONFIRMED SECURITY WEAKNESS.

## Controls Verified

- Query `skip` is constrained `ge=0`; `limit` is constrained `1..100` and is used in list ORM queries.
- Request-size middleware is intended to bound chunked and Content-Length requests, and backend tests exercise it.
- CORS uses an explicit comma-separated origin list by default, not wildcard origins. However `allow_credentials=True` and `allow_headers=["*"]` require deployment review.
- ORM filters use SQLAlchemy expressions; no SQL injection is claimed for ordinary ID filters.

## Missing Evidence

No live gateway test, reverse-proxy test, rate-limit test, CSRF/browser-token test, malformed payload corpus, or production error-response test was executed. UNVERIFIED — INSUFFICIENT EVIDENCE for server/proxy request limits after buffering, TLS, and WAF controls.
