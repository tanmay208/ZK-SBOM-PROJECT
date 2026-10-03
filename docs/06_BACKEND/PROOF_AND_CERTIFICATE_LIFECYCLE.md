# Proof, Verification, and Certificate Lifecycle

## Proof job

An authenticated request selects an SBOM/application, approved vulnerability snapshot, and active policy. The ZKP API creates a proof job and records progress, archive metadata, chunk/segment relationships, and terminal status. Proof generation completion is distinct from verification success.

## Verification

The verification API receives a proof-job identifier and expected public context. The verifier checks archive structure and proof members against the job and persisted records, invokes cryptographic verification where configured, and persists a result. The frontend offers completed jobs and submits proof_job_id; it invalidates verification and certificate queries after the mutation.

## Certificate lifecycle

A certificate is issued by the backend for a successful verified result. The certificate record includes issuance and revocation state. Private retrieval/revocation endpoints are authenticated and subject to backend authorization. Public validation returns the public validation contract and consults persisted revocation state. The frontend does not treat proof-job completion as a certificate or show an attached certificate as active for a non-verified result.

Implementation and historical execution claims are in source and the Stage21/22 reports. This summary does not claim a new live certificate issuance or proof verification.
