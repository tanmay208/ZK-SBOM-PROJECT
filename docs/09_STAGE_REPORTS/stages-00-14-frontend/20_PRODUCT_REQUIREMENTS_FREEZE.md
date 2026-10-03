# Product Requirements Freeze

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 4.1 Product Identity

- **Product Purpose:** A platform for vendors to generate zero-knowledge proofs (zk-SNARKs) that their software bill of materials (SBOMs) comply with a buyer's security policy regarding vulnerabilities, without revealing the SBOM contents to the buyer.
- **Problem Being Solved:** The conflict between a vendor's need to protect their proprietary software composition and a buyer's need to ensure the software they run is secure and free of severe vulnerabilities.
- **Security/Privacy Value:** Mathematical guarantee of vulnerability compliance (public data) without disclosing the underlying component identities or relationship graph (private data).
- **Intended Users:** Software vendors (proving compliance), software buyers/auditors (verifying compliance), and platform administrators (managing policies and intelligence).
- **Trust Boundary:** The vendor environment holds private data and generates proofs. The buyer environment receives only public commitments and proof artifacts. The platform's frontend operates on the buyer/vendor interface, managing the public artifacts and orchestrating the private proof generation for the vendor.
- **What the product intentionally protects:** Vendor's intellectual property (SBOM raw content, dependencies, PURLs, component names/versions).
- **What the frontend is responsible for:** Orchestrating API calls securely, strictly managing the in-memory access token, displaying public data accurately, restricting access by role, and correctly guiding users through the proof generation and verification lifecycles.
- **What the frontend must never do:** The frontend must never store sensitive data in persistent browser storage, log raw SBOM contents, attempt to authorize actions locally without server verification, or display fake security/cryptographic results before the backend confirms them.

## 4.2 Product Goals

- **Authentication:** Secure OAuth2 password flow with JWT bearer tokens. Tokens must be in-memory only.
- **Role-Aware Access:** Distinguish between `vendor`, `auditor`, and `admin` capabilities natively in the UI.
- **SBOM Submission:** Allow vendors to upload CycloneDX SBOMs (up to 10MB) for parsing, canonicalization, and Merkle tree generation.
- **SBOM Visibility:** Allow vendors to see metadata (name, format, status, root hash, component count) of their own uploaded SBOMs.
- **Vulnerability Intelligence:** Allow admins to ingest batch CVSS scores mapped to PURLs.
- **Vulnerability Snapshot Lifecycle:** Allow admins to approve or revoke point-in-time vulnerability SMT snapshots. Allow any user to view approved snapshots.
- **Security Policy Management:** Allow admins to create new active security policies (e.g., max CVSS score) that deactivate older policies. Allow any user to view policies.
- **Proof Generation:** Allow vendors to select an SBOM, a vulnerability snapshot, and a policy to asynchronously generate a zk-SNARK proof.
- **Proof Verification:** Allow any authenticated user to submit a proof along with expected public roots/hashes to cryptographically verify the claim.
- **Certificate/Result Presentation:** Provide immutable verification certificates upon successful verification. Make certificates publicly viewable by UUID.
- **Operational Metrics:** Provide user-scoped dashboard counts for SBOMs, proof jobs, verification requests, and certificates.
- **Administrative Workflows:** Enable admins to govern vulnerability intelligence and policy configurations.
- **Auditor Workflows:** Enable auditors to view public policies, snapshots, and verification certificates, and to perform verifications.

## 4.3 Product Non-Goals

The following are explicitly outside the product scope and must not be implemented:

- **Source-code scanning:** The platform does not scan code; it ingests SBOMs.
- **ML/AI vulnerability prediction:** Not used; relies on strict CVE/CVSS mappings.
- **Source-code disclosure:** Never occurs.
- **Unauthorized SBOM disclosure:** No API exists to fetch raw SBOMs.
- **Client-side authorization:** The frontend does not make ultimate access decisions; the server does.
- **Browser-side proof generation:** Not supported; nargo/bb run on the server (WSL).
- **Arbitrary vulnerability database modification by vendors:** Prohibited; ingestion is admin-only.
- **Unauthorized policy modification:** Prohibited; creation is admin-only.
- **Unsupported tenant/organization management:** No tenant/org grouping API exists; users are isolated as individuals.
- **Persistent sensitive browser storage:** The frontend must use in-memory state only for tokens and sensitive API responses.
- **Unsupported external artifact storage:** Proofs and SBOMs are stored in the SQL database, not external blobs (S3/GCS).
- **Audit logs UI:** The backend does not implement an audit log database table or API, so no audit log viewer can exist.

## 4.4 Actors

### Unauthenticated Visitor
- **Authentication requirement:** None.
- **Responsibilities:** Login, registration, viewing public certificates by direct URL.
- **Allowed areas:** `/login`, `/register`, `/certificates/{id}`.
- **Forbidden areas:** All other application routes.
- **Sensitive information:** None provided.

### Vendor
- **Authentication requirement:** JWT bearer token.
- **Responsibilities:** Uploading SBOMs, generating proofs.
- **Allowed areas:** Dashboard, SBOM management, Proof generation/management, Verification, Certificate listing, viewing Policies/Snapshots.
- **Forbidden areas:** Admin operations (vulnerability ingest, snapshot approve/revoke, policy creation).
- **Sensitive information:** Must not receive other vendors' SBOM data or proofs.

### Admin
- **Authentication requirement:** JWT bearer token with `admin` role.
- **Responsibilities:** Managing global vulnerability intelligence and security policies. Can also operate as a vendor.
- **Allowed areas:** All vendor areas, plus Admin configuration pages (Vulnerability ingest/manage, Policy creation).
- **Forbidden areas:** None structurally, but limited by user-scoped queries for SBOMs/Proofs (they can only see their own).
- **Sensitive information:** Must not receive raw PURLs in API responses from vulnerability ingestion (already handled by backend).

### Auditor
- **Authentication requirement:** JWT bearer token with `auditor` role.
- **Responsibilities:** Reviewing public commitments, verifying proofs, viewing certificates.
- **Allowed areas:** Dashboard, Verification, Certificate listing, viewing Policies/Snapshots.
- **Forbidden areas:** SBOM management, Proof generation, Admin operations.
- **Sensitive information:** Must never receive access to SBOMs, proof jobs, or raw vulnerability component mappings.
