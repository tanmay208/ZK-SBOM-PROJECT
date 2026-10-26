import hashlib
from datetime import datetime, timedelta
import jwt
import os
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from verification_service.app.models.verification_models import VerificationRequest, VerificationCertificate
from verification_service.app.schemas.verification_schemas import VerifyProofRequest


class VerificationRepository:
    """
    Repository for managing verification requests and certificates.
    """

    def __init__(self, session: Session):
        self._session = session

    def get_request_by_fingerprint(self, request: VerifyProofRequest, user_id: UUID) -> VerificationRequest | None:
        """
        Check if an identical request was already processed by this user.
        We check exact matches on the roots, policy, proof payload, AND the owner.
        """
        # Exact match query
        return self._session.query(VerificationRequest).filter(
            VerificationRequest.user_id == user_id,
            VerificationRequest.sbom_root == request.sbom_root,
            VerificationRequest.vulnerability_db_root == request.vulnerability_db_root,
            VerificationRequest.policy_hash == request.policy_hash,
            VerificationRequest.proof_job_id == request.proof_job_id
        ).first()

    def create_verification_record(self, request: VerifyProofRequest, result: str, user_id: UUID) -> VerificationRequest:
        """
        Persist a verification request and its certificate (if verified) atomically.
        This prevents partial state where a request is 'verified' but lacks a certificate.
        """
        req_record = VerificationRequest(
            sbom_root=request.sbom_root,
            vulnerability_db_root=request.vulnerability_db_root,
            policy_hash=request.policy_hash,
            proof_job_id=request.proof_job_id,
            result=result,
            verified_at=datetime.utcnow() if result == "verified" else None,
            user_id=user_id,
        )
        self._session.add(req_record)
        try:
            self._session.flush()  # Get ID without committing
        except IntegrityError:
            self._session.rollback()
            # PostgreSQL reports the unique-key race as an IntegrityError.
            # Only return a row after querying the exact tenant fingerprint;
            # unrelated constraint failures must still surface.
            existing = self.get_request_by_fingerprint(request, user_id)
            if existing:
                return existing
            raise
        
        if result == "verified":
            secret_str = os.environ.get("CERTIFICATE_SECRET_KEY")
            if not secret_str:
                raise ValueError("CERTIFICATE_SECRET_KEY must be configured for certificate signing")
            
            payload = {
                "sub": str(req_record.id),
                "iss": "antigravity-zkp-authority",
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(days=365),
                "sbom_root": request.sbom_root,
                "vulnerability_db_root": request.vulnerability_db_root,
                "policy_hash": request.policy_hash
            }
            
            token = jwt.encode(payload, secret_str, algorithm="HS256")
            
            cert = VerificationCertificate(
                verification_request_id=req_record.id,
                certificate_data=token,
                sbom_root=request.sbom_root,
                vulnerability_db_root=request.vulnerability_db_root,
                policy_hash=request.policy_hash
            )
            self._session.add(cert)
            
        try:
            self._session.commit()
            self._session.refresh(req_record)
        except IntegrityError:
            self._session.rollback()
            existing = self.get_certificate_by_request_id(req_record.id)
            if not existing:
                raise
            
        return req_record

    def update_verification_record(self, req_record: VerificationRequest, result: str) -> VerificationRequest:
        """
        Update an existing verification record and generate a certificate if newly verified.
        """
        req_record.result = result
        if result == "verified":
            req_record.verified_at = datetime.utcnow()
            secret_str = os.environ.get("CERTIFICATE_SECRET_KEY")
            if not secret_str:
                raise ValueError("CERTIFICATE_SECRET_KEY must be configured for certificate signing")
            
            payload = {
                "sub": str(req_record.id),
                "iss": "antigravity-zkp-authority",
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(days=365),
                "sbom_root": req_record.sbom_root,
                "vulnerability_db_root": req_record.vulnerability_db_root,
                "policy_hash": req_record.policy_hash
            }
            
            token = jwt.encode(payload, secret_str, algorithm="HS256")
            
            cert = VerificationCertificate(
                verification_request_id=req_record.id,
                certificate_data=token,
                sbom_root=req_record.sbom_root,
                vulnerability_db_root=req_record.vulnerability_db_root,
                policy_hash=req_record.policy_hash
            )
            self._session.add(cert)
            
        try:
            self._session.commit()
            self._session.refresh(req_record)
        except IntegrityError:
            self._session.rollback()
            if not self.get_certificate_by_request_id(req_record.id):
                raise
            
        return req_record

    def get_certificate(self, certificate_id: UUID) -> VerificationCertificate | None:
        """
        Retrieve a certificate by ID.
        """
        return self._session.query(VerificationCertificate).filter(
            VerificationCertificate.id == certificate_id
        ).first()

    def get_certificate_by_request_id(self, request_id: UUID) -> VerificationCertificate | None:
        """
        Retrieve a certificate by its associated request ID.
        """
        return self._session.query(VerificationCertificate).filter(
            VerificationCertificate.verification_request_id == request_id
        ).first()

    def validate_authoritative_records(self, sbom_root: str, vuln_root: str, policy_hash: str) -> bool:
        """
        Validate that the provided roots match active authoritative records.
        """
        from sbom_service.app.models.sbom_models import SBOMUpload
        from vulnerability_service.app.models.vulnerability_models import VulnerabilitySnapshot
        from policy_service.app.models.policy_models import SecurityPolicy
        
        # 1. Check SBOM
        sbom_exists = self._session.query(SBOMUpload).filter(
            SBOMUpload.sbom_root == sbom_root,
            SBOMUpload.status.in_(["committed", "completed"])
        ).first() is not None
        
        if not sbom_exists:
            return False
            
        # 2. Check Vulnerability Snapshot
        snapshot = (
            self._session.query(VulnerabilitySnapshot)
            .filter(VulnerabilitySnapshot.authoritative_smt_root == vuln_root)
            .first()
        )
        if not snapshot or snapshot.status != "frozen":
            return False
            
        # 3. Check Policy
        policy_exists = self._session.query(SecurityPolicy).filter(
            SecurityPolicy.policy_hash == policy_hash,
            SecurityPolicy.is_active == 1
        ).first() is not None
        
        if not policy_exists:
            return False
            
        return True

    def revoke_certificate(self, cert: VerificationCertificate, reason: str = None) -> VerificationCertificate:
        """
        Revoke an active certificate.

        Revocation is terminal and idempotent: a repeated request returns the
        original timestamp and reason instead of changing audit history.
        """
        current = self._session.query(VerificationCertificate).filter(
            VerificationCertificate.id == cert.id
        ).with_for_update().first()
        if current is None:
            raise LookupError("Certificate no longer exists")
        if current.is_revoked:
            return current

        current.is_revoked = True
        current.revoked_at = datetime.utcnow()
        current.revoked_reason = reason

        try:
            self._session.commit()
            self._session.refresh(current)
        except IntegrityError:
            self._session.rollback()
            raise
            
        return current
