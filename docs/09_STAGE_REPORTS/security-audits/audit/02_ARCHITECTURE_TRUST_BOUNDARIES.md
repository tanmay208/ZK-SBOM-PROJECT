# Architecture and Trust Boundaries

## Reconstructed Flow

Browser/static Next.js dashboard -> nginx gateway (referenced but absent) -> FastAPI service routes -> shared SQL Server instance with logical schemas. SBOM content is parsed and committed to an SBOM Merkle root. Vulnerability batches become snapshots and provisional SMT mappings. ZKP service reads SBOM, vulnerability, and policy records, writes a Prover.toml, invokes WSL/Nargo/Barretenberg, and stores a base64 proof. Verification service accepts public roots plus a base64 artifact, invokes Barretenberg, and issues a certificate if the subprocess exits zero.

## Boundaries

| Boundary | Trusted party | Untrusted input | Expected invariant | Enforcement/evidence |
|---|---|---|---|---|
| Browser -> API | API and token verifier | credentials, IDs, roots, proof, SBOM, vulnerability batch | authentication and schema validation before sensitive operations | schema validation is present; route auth is inconsistent; no global auth |
| Vendor SBOM -> SBOM service | parser/commitment pipeline | raw JSON, names, versions, PURLs, filename | bounded, canonical, private processing | 10 MB middleware, JSON parser, Pydantic fields; no explicit component-array limit before parse |
| API -> database | service transaction | IDs and normalized records | owner/role isolation and atomic writes | ORM parameterization and commits; ownership/role checks absent |
| Vulnerability feed -> snapshot | authoritative ingestion path | PURLs and CVSS values | only trusted source may create/freeze authoritative root | public unauthenticated ingest creates snapshots; root is documented provisional |
| DB records -> prover | trusted authoritative records | cross-schema references supplied by caller | proof binds intended SBOM, snapshot, policy | IDs are queried, but caller ownership/authority is not checked |
| Prover -> WSL tools | local host/toolchain | generated filenames and data-derived TOML | fixed executable/profile, bounded process, isolated cleanup | argument arrays for Nargo; `bash -c` for bb; timeouts/cleanup exist; production toolchain unavailable |
| Proof -> verifier | verifier key and circuit | base64 proof and caller-supplied roots | genuine proof under authoritative key and roots | subprocess exit code gates certificate; roots are not looked up or compared to an authority registry |
| API -> logs/responses | service operators/buyers | private SBOM and internal errors | no private data or paths leak | redaction filter exists; proof job returns `error_message`; coverage is pattern-based |

## Client Influence Points

The client can supply username/password, SBOM application/vendor/filename/format/content, vulnerability PURLs and scores, policy values, SBOM/snapshot/policy IDs for proof jobs, verification roots and policy hash, proof artifacts, certificate IDs, pagination offsets/limits, and bearer tokens. The client cannot directly supply a role during registration because registration hardcodes `auditor`, but no route-level role enforcement exists.

## Trust Conclusions

The shared database is treated as trusted by services, but all five services use the same database credentials in Compose and no database-level least-privilege evidence was found. Public roots are treated as caller-provided verification inputs rather than resolved authoritative commitments. Production cryptographic deployment is UNVERIFIED — INSUFFICIENT EVIDENCE.
