# Data Flow

1. **Authentication:** the frontend obtains an access token from the auth API and retains it in memory. Authenticated API calls send it as a bearer token.
2. **SBOM intake:** the SBOM service accepts an upload, parses and validates components, resolves identities, canonicalizes data, and persists application/SBOM records and commitments.
3. **Verification context:** the user selects an approved vulnerability snapshot and an active policy. The backend persists snapshot/policy information and associates them with proof work.
4. **Proof job:** the ZKP API creates a proof job, prepares witnesses, invokes configured Noir/Barretenberg tools, and persists proof/archive metadata and segment records.
5. **Application verification:** the verification API receives the proof job reference and public context, validates proof material and bindings, records a result, and issues a certificate for a successful verified result.
6. **Public status:** the frontend displays the backend result and only links a certificate when verified. Public certificate validation is a separate unauthenticated status endpoint; it does not return private certificate data.

This sequence describes code paths, not a guarantee that every external dependency or live deployment is available. Stage 22.9 did not execute the full authenticated flow against a running backend.
