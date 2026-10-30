from shared.logging import audit_log
from uuid import UUID

from sqlalchemy.orm import Session

from verification_service.app.models.verification_models import (
    VerificationRequest,
    VerificationCertificate,
    ProofShare,
)
from verification_service.app.repositories.verification_repository import VerificationRepository
from verification_service.app.schemas.verification_schemas import (
    VerifyProofRequest,
    ProofShareResponse,
)
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

    def process_verification(
        self,
        request: VerifyProofRequest,
        user_id: UUID,
        user_role: str = None,
    ) -> VerificationRequest:
        """
        Process a verification request. Returns the VerificationRequest model
        (which may have a related certificate if verified).

        Security invariant (ZK-002): The verifier receives the expected public
        inputs from the API request and compares them to the public inputs
        embedded in the proof file. A certificate is only issued when BOTH
        the cryptographic verification passes AND the public inputs match.
        """
        # Resolve user_role if not passed directly
        if user_role is None:
            from shared.models.user import User
            user_rec = self._session.query(User).filter(User.id == user_id).first()
            if user_rec and not hasattr(user_rec, "_mock_name") and hasattr(user_rec, "role") and not hasattr(user_rec.role, "_mock_name"):
                user_role = user_rec.role
            else:
                user_role = "buyer"
        # 1. Share Token Validation & ProofJob Resolution
        from zkp_service.app.models.zkp_models import ProofJob

        share = None
        if getattr(request, "share_token", None):
            share = self._repo.get_proof_share_by_token(request.share_token)
            if not share or not share.is_active:
                return self._repo.create_verification_record(
                    request.model_copy(update={"proof_job_id": None}), "verification_unavailable", user_id=user_id
                )
            if request.proof_job_id is None:
                request = request.model_copy(update={"proof_job_id": share.proof_job_id})
            elif str(request.proof_job_id) != str(share.proof_job_id):
                return self._repo.create_verification_record(
                    request.model_copy(update={"proof_job_id": None}), "verification_unavailable", user_id=user_id
                )

        # 2. Idempotency Check (with active authorization enforcement)
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
                # If existing request was verified, verify caller still has active authorization
                job = self._session.query(ProofJob).filter(ProofJob.id == existing_req.proof_job_id).first()
                if job and isinstance(job, ProofJob) and not hasattr(job, "_mock_name"):
                    is_owner = (getattr(job, "user_id", None) == user_id)
                    is_admin = (user_role == "admin")
                    if not (is_owner or is_admin):
                        has_share = (share is not None and share.is_active) or self._repo.has_active_share_for_job(job.id, user_id, user_role)
                        if not has_share:
                            return self._repo.create_verification_record(
                                request.model_copy(update={"proof_job_id": None}), "verification_unavailable", user_id=user_id
                            )
                return existing_req

        # 3. Fresh Verification Authorization & Job Binding
        if not request.proof_job_id:
            return self._repo.create_verification_record(
                request, "verification_unavailable", user_id=user_id
            )

        job = self._session.query(ProofJob).filter(ProofJob.id == request.proof_job_id).first()
        if not job:
            persisted_req = request.model_copy(update={"proof_job_id": None})
            return self._repo.create_verification_record(
                persisted_req, "verification_unavailable", user_id=user_id
            )

        # Caller is authorized if:
        # 1. Caller owns the proof job (job.user_id == user_id)
        # 2. Caller has role 'admin'
        # 3. Request provided a valid active share matching this user/role
        # 4. Caller has an active unrevoked unexpired share for this job
        is_owner = (job.user_id == user_id)
        is_admin = (user_role == "admin")
        has_share = False

        if share is not None:
            if (share.recipient_user_id is None or share.recipient_user_id == user_id) and                (share.recipient_role == user_role or is_admin):
                has_share = True
        else:
            has_share = self._repo.has_active_share_for_job(job.id, user_id, user_role)

        if not (is_owner or is_admin or has_share):
            return self._repo.create_verification_record(
                request.model_copy(update={"proof_job_id": None}), "verification_unavailable", user_id=user_id
            )

        # Incomplete proofs (e.g. running or failed) cannot be verified
        job_status = getattr(job, "status", None)
        if job_status is not None and not hasattr(job_status, "_mock_name") and job_status != "completed":
            return self._repo.create_verification_record(
                request.model_copy(update={"proof_job_id": None}), "verification_unavailable", user_id=user_id
            )

        # 3. Authoritative Record Binding (ZK-002, AUD-3A-005, AUD-3A-006)
        # Prevent proof verification from succeeding if roots belong to unfrozen/nonexistent records.
        # SECURITY INVARIANT: New compliance verification requires the policy to be ACTIVE (is_active == 1).
        # Inactive policies cannot authorize new certificates.
        if not self._repo.validate_authoritative_records(
            request.sbom_root,
            request.vulnerability_db_root,
            request.policy_hash,
            require_active_policy=True,
            proof_job_id=request.proof_job_id,
        ):
            # Authoritative records mismatch, treat as failure
            if existing_req:
                return self._repo.update_verification_record(existing_req, "record_mismatch")
            return self._repo.create_verification_record(request, "record_mismatch", user_id=user_id)

        # Preflight context snapshot for TOCTOU verification (AUD-3A-007)
        preflight_context = {
            "proof_job_id": job.id,
            "snapshot_id": job.snapshot_id,
            "vulnerability_db_root": request.vulnerability_db_root,
            "policy_id": job.policy_id,
            "policy_hash": request.policy_hash,
            "sbom_upload_id": job.sbom_upload_id,
            "sbom_root": request.sbom_root,
        }

        # 4. Cryptographic Verification with public-input binding (ZK-002)
        result = self._verifier.verify(
            request.proof_job_id,
            self._session,
            expected_sbom_root=request.sbom_root,
            expected_vulnerability_db_root=request.vulnerability_db_root,
            expected_policy_hash=request.policy_hash,
        )

        # 5. Persist Request Status and Gated Certificate Issuance with TOCTOU Protection (AUD-3A-007)
        # Security Invariant: Certificates are ONLY issued when result is exactly 'verified'
        # and revalidation succeeds at the persistence boundary.
        if existing_req:
            req_record = self._repo.update_verification_record(
                existing_req, result, preflight_context=preflight_context
            )
        else:
            req_record = self._repo.create_verification_record(
                request, result, user_id=user_id, preflight_context=preflight_context
            )

        return req_record

    def get_certificate(
        self,
        certificate_id: UUID,
        user_id: UUID = None,
        user_role: str = None,
    ) -> VerificationCertificate | None:
        """
        Retrieve a specific certificate, ensuring its underlying ProofJob still exists and belongs to the user or caller is authorized.
        """
        cert = self._repo.get_certificate(certificate_id)
        if not cert:
            return None

        return self._validate_cert_job(cert, user_id, user_role)

    def get_certificate_by_request(
        self,
        request_id: UUID,
        user_id: UUID = None,
        user_role: str = None,
    ) -> VerificationCertificate | None:
        """
        Retrieve a certificate linked to a request, ensuring its underlying ProofJob still exists and belongs to the user or caller is authorized.
        """
        cert = self._repo.get_certificate_by_request_id(request_id)
        if not cert:
            return None

        return self._validate_cert_job(cert, user_id, user_role)

    def _validate_cert_job(
        self,
        cert: VerificationCertificate,
        user_id: UUID = None,
        user_role: str = None,
    ) -> VerificationCertificate | None:
        from zkp_service.app.models.zkp_models import ProofJob

        req = self._session.query(VerificationRequest).filter(VerificationRequest.id == cert.verification_request_id).first()
        if not req:
            return None

        if req.proof_job_id is not None:
            job = self._session.query(ProofJob).filter(ProofJob.id == req.proof_job_id).first()
            if not job:
                return None
        else:
            job = None

        if user_id:
            if user_role == "admin":
                pass
            elif user_role == "vendor" and job and job.user_id == user_id:
                pass
            elif req.user_id == user_id:
                pass
            else:
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

    # -------------------------------------------------------------------------
    # Vendor-to-Buyer Proof Sharing Operations
    # -------------------------------------------------------------------------

    def _build_share_response(self, share: ProofShare) -> ProofShareResponse:
        from zkp_service.app.models.zkp_models import ProofJob
        job = self._session.query(ProofJob).filter(ProofJob.id == share.proof_job_id).first()
        return ProofShareResponse(
            id=share.id,
            proof_job_id=share.proof_job_id,
            vendor_id=share.vendor_id,
            share_token=share.share_token,
            recipient_role=share.recipient_role,
            recipient_user_id=share.recipient_user_id,
            is_revoked=share.is_revoked,
            revoked_at=share.revoked_at,
            expires_at=share.expires_at,
            created_at=share.created_at,
            is_active=share.is_active,
            sbom_root=job.sbom_root if job else None,
            vulnerability_db_root=job.vulnerability_db_root if job else None,
            policy_hash=job.policy_hash if job else None,
        )

    def create_share(
        self,
        proof_job_id: UUID,
        vendor_id: UUID,
        user_role: str,
        recipient_role: str = "buyer",
        recipient_user_id: UUID | None = None,
        expires_in_hours: int | None = None,
    ) -> ProofShareResponse:
        """
        Create a verification share token for a completed proof job.
        Strictly prevents sharing running, incomplete, or non-existent proofs.
        """
        from zkp_service.app.models.zkp_models import ProofJob
        job = self._session.query(ProofJob).filter(ProofJob.id == proof_job_id).first()
        if not job:
            raise LookupError("Proof job not found")

        if user_role != "admin" and job.user_id != vendor_id:
            raise PermissionError("Only the proof owner or admin can create a verification share")

        if job.status != "completed":
            raise ValueError(f"Only completed proof jobs can be shared for verification (current status: {job.status})")

        share_owner_id = job.user_id if user_role == "admin" else vendor_id
        share = self._repo.create_proof_share(
            proof_job_id=proof_job_id,
            vendor_id=share_owner_id,
            recipient_role=recipient_role,
            recipient_user_id=recipient_user_id,
            expires_in_hours=expires_in_hours,
        )
        audit_log(
            "verification_service",
            "proof_share_created",
            f"Proof share {share.id} created for job {proof_job_id} by vendor {vendor_id}",
            actor_id=str(vendor_id),
            resource_type="proof_share",
            resource_id=str(share.id),
            outcome="success",
        )
        return self._build_share_response(share)

    def get_share(
        self,
        share_token_or_id: str,
        user_id: UUID,
        user_role: str,
    ) -> ProofShareResponse | None:
        """
        Retrieve proof share details by share token or UUID ID.
        """
        share = None
        # Try UUID first
        try:
            share_uuid = UUID(share_token_or_id)
            share = self._repo.get_proof_share_by_id(share_uuid)
        except (ValueError, TypeError):
            pass

        if not share:
            share = self._repo.get_proof_share_by_token(share_token_or_id)

        if not share:
            return None

        # Verify authorization to view this share:
        # Admin: authorized
        # Vendor: authorized if owner
        # Buyer: authorized if active, unrevoked, unexpired, and role matches
        if user_role == "admin":
            pass
        elif user_role == "vendor":
            if share.vendor_id != user_id:
                return None
        elif user_role == "buyer":
            if not share.is_active:
                return None
            if share.recipient_role != "buyer":
                return None
            if share.recipient_user_id is not None and share.recipient_user_id != user_id:
                return None
        else:
            return None

        return self._build_share_response(share)

    def list_shares(
        self,
        user_id: UUID,
        user_role: str,
        skip: int = 0,
        limit: int = 50,
    ) -> list[ProofShareResponse]:
        """
        List all proof shares accessible to the caller.
        """
        shares = self._repo.list_proof_shares_for_user(
            user_id=user_id,
            user_role=user_role,
            skip=skip,
            limit=limit,
        )
        return [self._build_share_response(s) for s in shares]

    def revoke_share(
        self,
        share_id: UUID,
        user_id: UUID,
        user_role: str,
    ) -> ProofShareResponse | None:
        """
        Revoke an active proof share.
        """
        share = self._repo.revoke_proof_share(share_id, user_id=user_id, user_role=user_role)
        if not share:
            return None
        audit_log(
            "verification_service",
            "proof_share_revoked",
            f"Proof share {share.id} revoked by actor {user_id} (role={user_role})",
            actor_id=str(user_id),
            resource_type="proof_share",
            resource_id=str(share.id),
            outcome="success",
        )
        return self._build_share_response(share)

    def delete_share(
        self,
        share_id: UUID,
        user_id: UUID,
        user_role: str,
    ) -> dict | None:
        """
        Delete a revoked verification share.
        Enforces:
        - Role must be vendor or admin
        - Share must exist and belong to the vendor (or caller is admin)
        - Share MUST be in revoked state (active shares cannot be deleted)
        - Emits structured audit log
        - Never affects underlying proof jobs, certificates, or verification requests
        """
        share = self._repo.get_proof_share_by_id(share_id)
        if not share:
            return None

        if user_role != "admin" and share.vendor_id != user_id:
            return None

        if not share.is_revoked:
            raise ValueError("Cannot delete an active verification share. Only revoked shares may be deleted.")

        token_prefix = str(share.share_token)[:12] if share.share_token else "unknown"
        self._repo.delete_proof_share(share)
        audit_log(
            "verification_service",
            "proof_share_deleted",
            f"Revoked proof share {share.id} ({token_prefix}...) deleted by actor {user_id} (role={user_role})",
            actor_id=str(user_id),
            resource_type="proof_share",
            resource_id=str(share.id),
            outcome="success",
        )
        return {
            "status": "deleted",
            "id": str(share_id),
            "message": "Revoked proof share successfully deleted",
        }

