# Secrets, Privacy, Logging, and Privacy Audit

## Evidence

- `.env.example` has an empty DB password placeholder and no JWT secret value. Compose requires `DB_PASSWORD` at interpolation time.
- `gitleaks` found no leaks in one commit and about 36.6 KB scanned.
- `SecurityAwareFilter` sanitizes a limited set of regex patterns and field names; service logging setup was inspected in `backend/shared/logging.py`.
- SBOM upload response excludes raw content, PURLs, and component hashes. Auth responses exclude password hashes.

## Findings

- Prover failure messages include subprocess stderr; unexpected failures store `str(e)`. `ProofJobResponse` returns `error_message`, and job retrieval is unauthenticated. Internal paths, commands, or private data could leak. Classification: CONFIRMED SECURITY WEAKNESS.
- Pattern-based redaction is not a general data-loss-prevention control. Names, versions, arbitrary JSON, and raw content not matching patterns may pass. Classification: SECURITY WEAKNESS.
- Snapshot list explicitly returns `provisional_smt_root` even though ingestion response documentation says the provisional root is not exposed. Classification: CONFIRMED contract/privacy weakness.
- Database columns retain raw SBOM and proof artifacts; no retention/deletion policy, encryption evidence, or crash cleanup policy was found. Classification: HARDENING RECOMMENDATION / UNVERIFIED impact.
- `DB_ECHO` can enable SQL logging if configured true; no production configuration guard was found. Classification: HARDENING RECOMMENDATION.

## False Positive

The apparent password-hash response leak is a FALSE POSITIVE for the inspected auth handlers: registration, login, and `/me` build explicit dictionaries without `hashed_password`. This does not cover future generic ORM responses.

## Limitations

No live logs, CI logs, database backups, crash dumps, or production secret store were available. UNVERIFIED — INSUFFICIENT EVIDENCE for those channels.
