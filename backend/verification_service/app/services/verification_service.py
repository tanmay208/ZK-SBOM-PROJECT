from shared.logging import audit_log
from uuid import UUID

from sqlalchemy.orm import Session

from verification_service.app.models.verification_models import VerificationRequest, VerificationCertificate
from verification_service.app.repositories.verification_repository import VerificationRepository
from verification_service.app.schemas.verification_schemas import VerifyProofRequest
from verification_service.app.core.verifier import NoirVerifier


class VerificationService:
    """
    Business logic for processing verification requests, enforcing idempotency,
    and gating certificate creation based on strict cryptographic success.
    """

    def __init__(self, session: Session, verifier=None):
        self._session = session
        self._repo = VerificationRepository(session)
        self._verifier = verifier if verifier else NoirVerifier()

    def process_verification(self, request: VerifyProofRequest, user_id: UUID) -> VerificationRequest:
        """
        Process a verification request. Returns the VerificationRequest model
        (which may have a related certificate if verified).

        Security invariant (ZK-002): The verifier receives the expected public
        inputs from the API request and compares them to the public inputs
        embedded in the proof file. A certificate is only issued when BOTH
        the cryptographic verification passes AND the public inputs match.
        """
        # 1. Idempotency Check
        existing_req = self._repo.get_request_by_fingerprint(request, user_id)
        if existing_req:
            if existing_req.result in [
                "record_mismatch",
                "unavailable",
                "verification_unavailable",
                "runtime_failure",
                "environment_failure",
            ]:
                pass # re-evaluate operational / transient failures
            else:
                return existing_req

        # 2. Bind the request to an owned ProofJob before checking any
        # authoritative records. This keeps missing and foreign job IDs
        # indistinguishable from an unavailable verification.
        from zkp_service.app.models.zkp_models import ProofJob
        job = self._session.query(ProofJob).filter(
            ProofJob.id == request.proof_job_id,
            ProofJob.user_id == user_id,
        ).first()
        if not job or job.user_id != user_id:
            if existing_req:
                return self._repo.update_verification_record(existing_req, "verification_unavailable")
            # If proof_job_id does not exist in zkp.proof_jobs at all, we clear it
            # so the DB foreign key constraint (proof_job_id -> zkp.proof_jobs.id) is preserved.
            persisted_req = request
            if request.proof_job_id is not None:
                job_in_db = self._session.query(ProofJob).filter(ProofJob.id == request.proof_job_id).first()
                if not job_in_db:
                    persisted_req = request.model_copy(update={"proof_job_id": None})
            return self._repo.create_verification_record(
                persisted_req, "verification_unavailable", user_id=user_id
            )

        # 3. Authoritative Record Binding (ZK-002)
        # Prevent proof verification from succeeding if roots belong to unfrozen/nonexistent records.
        # SECURITY INVARIANT: New compliance verification requires the policy to be ACTIVE (is_active == 1).
        # Inactive policies cannot authorize new certificates.
        if not self._repo.validate_authoritative_records(
            request.sbom_root, request.vulnerability_db_root, request.policy_hash, require_active_policy=True
        ):
        # Authoritative records mismatch, treat as failure
            if existing_req:
                return self._repo.update_verification_record(existing_req, "record_mismatch")
            return self._repo.create_verification_record(request, "record_mismatch", user_id=user_id)

        # 4. Cryptographic Verification with public-input binding (ZK-002)
        result = self._verifier.verify(
            request.proof_job_id,
            self._session,
            expected_sbom_root=request.sbom_root,
            expected_vulnerability_db_root=request.vulnerability_db_root,
            expected_policy_hash=request.policy_hash,
        )

        # 4. Persist Request Status and Gated Certificate Issuance (Atomic)
        # Security Invariant: Certificates are ONLY issued when result is exactly 'verified'.
        # 'public_input_mismatch' is treated as a verification failure — no certificate.
        if existing_req:
            req_record = self._repo.update_verification_record(existing_req, result)
        else:
            req_record = self._repo.create_verification_record(request, result, user_id=user_id)

        return req_record

    def get_certificate(self, certificate_id: UUID, user_id: UUID = None) -> VerificationCertificate | None:
        """
        Retrieve a specific certificate, ensuring its underlying ProofJob still exists and belongs to the user.
        """
        cert = self._repo.get_certificate(certificate_id)
        if not cert:
            return None

        return self._validate_cert_job(cert, user_id)

    def get_certificate_by_request(self, request_id: UUID, user_id: UUID = None) -> VerificationCertificate | None:
        """
        Retrieve a certificate linked to a request, ensuring its underlying ProofJob still exists and belongs to the user.
        """
        cert = self._repo.get_certificate_by_request_id(request_id)
        if not cert:
            return None

        return self._validate_cert_job(cert, user_id)

    def _validate_cert_job(self, cert: VerificationCertificate, user_id: UUID = None) -> VerificationCertificate | None:
        from zkp_service.app.models.zkp_models import ProofJob

        req = self._session.query(VerificationRequest).filter(VerificationRequest.id == cert.verification_request_id).first()
        if not req:
            return None

        if user_id and req.user_id != user_id:
            return None

        if req.proof_job_id is not None:
            job = self._session.query(ProofJob).filter(ProofJob.id == req.proof_job_id).first()
            if not job:
                return None

        return cert

    def revoke_certificate(
        self,
        certificate_id: UUID,
        user_id: UUID,
        reason: str = None,
        user_role: str = "vendor",
    ) -> VerificationCertificate | None:
        """
        Revoke a certificate if authorized.

        Authorization rules:
        - 'admin': Authorized to revoke any eligible certificate across tenants.
        - 'vendor': Authorized to revoke only certificates belonging to their own tenant/requests.
        - Other roles (auditor, buyer, trusted_importer): Unauthorized to revoke.
        """
        if user_role == "admin":
            cert = self._repo.get_certificate(certificate_id)
            if not cert:
                return None
            req = self._session.query(VerificationRequest).filter(
                VerificationRequest.id == cert.verification_request_id
            ).first()
            if not req:
                return None
        elif user_role == "vendor":
            cert = self.get_certificate(certificate_id, user_id=user_id)
            if not cert:
                audit_log(
                    "verification_service",
                    "certificate_revocation",
                    f"Certificate {certificate_id} not found or unauthorized for vendor {user_id}",
                    actor_id=str(user_id),
                    resource_type="verification_certificate",
                    resource_id=str(certificate_id),
                    outcome="denied",
                )
                return None
        else:
            audit_log(
                "verification_service",
                "certificate_revocation",
                f"Unauthorized role '{user_role}' attempted certificate revocation for {certificate_id}",
                actor_id=str(user_id),
                resource_type="verification_certificate",
                resource_id=str(certificate_id),
                outcome="denied",
            )
            return None

        try:
            revoked_cert = self._repo.revoke_certificate(cert, reason=reason, revoked_by=user_id)
            if revoked_cert:
                audit_log(
                    "verification_service",
                    "certificate_revocation",
                    f"Certificate {certificate_id} revoked by actor {user_id} (role={user_role})",
                    actor_id=str(user_id),
                    resource_type="verification_certificate",
                    resource_id=str(certificate_id),
                    outcome="success",
                )
            return revoked_cert
        except LookupError:
            # A concurrent cascade/delete must have the same anti-enumeration
            # response as an unknown certificate.
            audit_log(
                "verification_service",
                "certificate_revocation",
                f"Certificate revocation lookup error for {certificate_id} by actor {user_id}",
                actor_id=str(user_id),
                resource_type="verification_certificate",
                resource_id=str(certificate_id),
                outcome="denied",
            )
            return None

    def validate_certificate(self, certificate_id: UUID) -> dict:
        """
        Validate whether a certificate is currently accepted as valid.

        This is the AUTHORITATIVE validation path.  A certificate that has
        been revoked (is_revoked=True in the database) MUST NOT be accepted
        as currently valid, regardless of whether a previously-copied JWT
        token would still pass signature verification.

        Returns a dict with:
          - valid: bool
          - reason: str  (human-readable explanation)
          - certificate_id: str
          - is_revoked: bool | None
          - revoked_at: datetime | None
        """
        cert = self._repo.get_certificate(certificate_id)
        if not cert:
            return {
                "valid": False,
                "reason": "certificate_not_found",
                "certificate_id": str(certificate_id),
                "is_revoked": None,
                "revoked_at": None,
            }

        if cert.is_revoked:
            return {
                "valid": False,
                "reason": "certificate_revoked",
                "certificate_id": str(certificate_id),
                "is_revoked": True,
                "revoked_at": cert.revoked_at,
            }

        # Verify the underlying request and proof job still exist
        req = self._session.query(VerificationRequest).filter(
            VerificationRequest.id == cert.verification_request_id
        ).first()
        if not req or req.result != "verified":
            return {
                "valid": False,
                "reason": "underlying_request_invalid",
                "certificate_id": str(certificate_id),
                "is_revoked": False,
                "revoked_at": None,
            }

        return {
            "valid": True,
            "reason": "certificate_active",
            "certificate_id": str(certificate_id),
            "is_revoked": False,
            "revoked_at": None,
        }

    def validate_certificate_token(self, token: str) -> dict:
        """
        Validate a previously-issued JWT certificate token against the
        authoritative revocation state.

        Even if the JWT signature is valid, the certificate is rejected
        when the database record shows is_revoked=True.  This prevents
        previously-copied tokens from bypassing revocation.

        Returns a dict with:
          - valid: bool
          - reason: str
          - certificate_id: str | None
        """
        import jwt as pyjwt
        import os
        import json

        keys_config = os.environ.get("CERTIFICATE_SECRET_KEYS")
        default_secret = os.environ.get("CERTIFICATE_SECRET_KEY")

        keys = {}
        if keys_config:
            try:
                keys = json.loads(keys_config)
            except json.JSONDecodeError:
                return {
                    "valid": False,
                    "reason": "server_configuration_error",
                    "certificate_id": None,
                }
        if default_secret:
            if "legacy" not in keys:
                keys["legacy"] = default_secret
            if "v1" not in keys:
                keys["v1"] = default_secret

        if not keys:
            return {
                "valid": False,
                "reason": "server_configuration_error",
                "certificate_id": None,
            }

        try:
            unverified_header = pyjwt.get_unverified_header(token)
            kid = unverified_header.get("kid", "legacy")
        except pyjwt.PyJWTError:
            return {
                "valid": False,
                "reason": "token_invalid",
                "certificate_id": None,
            }

        if kid not in keys:
            return {
                "valid": False,
                "reason": "unknown_key_id",
                "certificate_id": None,
            }

        secret = keys[kid]

        try:
            payload = pyjwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                issuer="antigravity-zkp-authority"
            )
        except pyjwt.ExpiredSignatureError:
            return {
                "valid": False,
                "reason": "token_expired",
                "certificate_id": None,
            }
        except pyjwt.InvalidTokenError:
            return {
                "valid": False,
                "reason": "token_invalid",
                "certificate_id": None,
            }

        request_id = payload.get("sub")
        if not request_id:
            return {
                "valid": False,
                "reason": "token_missing_subject",
                "certificate_id": None,
            }

        # Look up the certificate by its verification_request_id
        cert = self._repo.get_certificate_by_request_id(UUID(request_id))
        if not cert:
            return {
                "valid": False,
                "reason": "certificate_not_found",
                "certificate_id": None,
            }

        # CRITICAL: Even though the JWT signature passes, authoritative
        # database state (revocation and historical record validity) takes precedence.
        cert_val = self.validate_certificate(cert.id)
        if not cert_val["valid"]:
            return {
                "valid": False,
                "reason": cert_val["reason"],
                "certificate_id": str(cert.id),
            }

        return {
            "valid": True,
            "reason": "certificate_active",
            "certificate_id": str(cert.id),
        }

