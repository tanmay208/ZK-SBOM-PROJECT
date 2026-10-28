# False-Positive Analysis

## SQL Injection

Initially dangerous because IDs and values cross API/database boundaries. Inspected SQLAlchemy ORM filters and `ensure_schemas`, whose schema names are fixed constants. No user SQL string reaches those queries. Classification: FALSE POSITIVE for inspected paths; raw SQL and database permissions remain unverified.

## JWT Algorithm Confusion

Initially dangerous because JWTs are client-presented. Inspected `create_access_token` and `get_current_user`: encoding fixes HS256 and decoding restricts algorithms to HS256 while requiring `exp` and `sub`. Classification: FALSE POSITIVE for algorithm confusion; missing issuer/audience/revocation remain weaknesses.

## Password Hash Disclosure

Initially dangerous because the User model contains `hashed_password`. Inspected register, login, and `/me` response dictionaries; none return the hash. Classification: FALSE POSITIVE for these handlers, not a blanket guarantee for future ORM responses.

## Shell Injection Through Job IDs

Initially dangerous because Barretenberg is invoked via `bash -c`. Inspected interpolation sources: job IDs are UUID database values and verification IDs are generated with `uuid4().hex`; the request schema does not accept command text. Classification: FALSE POSITIVE for demonstrated direct injection, with hardening recommendation to eliminate `bash -c`.

## Unbounded Pagination

Initially dangerous because list routes accept `skip` and `limit`. Inspected schemas and ORM calls: limit is constrained to 100 and passed to `.limit()`. Classification: FALSE POSITIVE for a declared-limit bypass; aggregate counts and repeated-page abuse remain rate/resource concerns.

## Duplicate Omission

Initially dangerous because duplicate component identities are classified. Inspected identity resolver and commitment service: all components remain in the ordered list and count. Classification: FALSE POSITIVE for silent duplicate omission; identity mismatch across PURL/name representations remains a weakness.

## Certificate Without Verification

Initially dangerous because certificate data is a simple SHA-256-derived string. Inspected repository gating: certificate creation occurs only when verifier status is exactly `verified`. Classification: FALSE POSITIVE for the specific missing-gate claim. The separate authoritative-root binding defect remains confirmed.

## Passing Backend Tests as Proof

Initially tempting because 480 backend tests pass. Test fixtures include mocks/test doubles and no live production toolchain/DB. Classification: FALSE POSITIVE as a security conclusion; tests are evidence only for exercised cases.

## Gitleaks Clean Result

Initially reassuring because no leaks were reported. The scanner covered one commit and current scan limitations do not cover every remote/deleted artifact or semantic secret. Classification: FALSE POSITIVE as a complete secret-clearance claim.

## No Confirmed Cryptographic Bypass

Fake/mutated proof artifacts exist, but Nargo and Barretenberg were unavailable and no verifier bypass was reproduced. Classification: UNVERIFIED — INSUFFICIENT EVIDENCE, not a confirmed forgery vulnerability.
