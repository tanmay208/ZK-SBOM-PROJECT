import hashlib
import re
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.types import UUID4


class VerifyProofRequest(BaseModel):
    """
    Buyer-initiated request to verify a zero-knowledge proof against public commitments.
    CRITICAL: This payload must only accept public roots, never raw private components.
    """
    model_config = ConfigDict(extra="forbid")

    sbom_root: str = Field(..., min_length=2, max_length=128, description="The authoritative SBOM merkle root")
    vulnerability_db_root: str = Field(..., min_length=2, max_length=128, description="The authoritative Vulnerability SMT root")
    policy_hash: str = Field(..., min_length=2, max_length=128, description="The authoritative Policy hash")
    proof_job_id: UUID4 | None = Field(None, description="The ID of the ProofJob containing the 256 chunk proofs")
    proof_artifact: str | None = Field(None, max_length=10_000_000, description="Optional legacy string proof artifact from frontend payload")
    share_token: str | None = Field(None, max_length=64, description="Optional verification reference / share token")

    @field_validator("sbom_root", "vulnerability_db_root", "policy_hash")
    @classmethod
    def validate_hex(cls, v: str) -> str:
        if not re.match(r"^0x[a-fA-F0-9]{64}$", v):
            raise ValueError("Root/Hash must be a strictly formatted 0x-prefixed 64-character hex string")
        return v


class VerificationCertificateResponse(BaseModel):
    """
    Public representation of an issued verification certificate.
    """
    id: UUID4
    verification_request_id: UUID4
    certificate_data: str | None = None
    sbom_root: str
    vulnerability_db_root: str
    policy_hash: str
    issued_at: datetime
    is_revoked: bool = False
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    revoked_by: UUID4 | None = None
    sha256_fingerprint: str | None = None

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode='before')
    @classmethod
    def sanitize_attributes(cls, data: object) -> object:
        if isinstance(data, dict):
            return data
        # Handle MagicMock / test doubles where accessing unconfigured fields returns mock instances
        attrs = {}
        for field in [
            "id", "verification_request_id", "certificate_data", "sbom_root",
            "vulnerability_db_root", "policy_hash", "issued_at", "is_revoked",
            "revoked_at", "revoked_reason", "revoked_by", "sha256_fingerprint"
        ]:
            val = getattr(data, field, None)
            if hasattr(val, "_mock_name"):
                attrs[field] = None
            else:
                attrs[field] = val
        return attrs

    @model_validator(mode='after')
    def compute_fingerprint_and_mask(self) -> 'VerificationCertificateResponse':
        if not self.sha256_fingerprint and self.certificate_data:
            self.sha256_fingerprint = hashlib.sha256(self.certificate_data.encode("utf-8")).hexdigest()
        if self.is_revoked:
            self.certificate_data = None
        return self



class VerificationResponse(BaseModel):
    """
    Public status response of a verification request.
    """
    id: UUID4
    sbom_root: str
    vulnerability_db_root: str
    policy_hash: str
    result: str | None = None
    verified_at: datetime | None = None
    created_at: datetime

    certificate: VerificationCertificateResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class RevokeCertificateRequest(BaseModel):
    """
    Request to revoke a verification certificate.
    """
    reason: str | None = Field(None, max_length=255, description="Reason for revocation")


class CreateProofShareRequest(BaseModel):
    """
    Vendor-initiated request to share a completed proof job for verification.
    """
    model_config = ConfigDict(extra="forbid")

    proof_job_id: UUID4 = Field(..., description="The ID of the completed ProofJob to share")
    recipient_role: str = Field("buyer", pattern="^(buyer|vendor|admin)$", description="Role permitted to use this share")
    recipient_user_id: UUID4 | None = Field(None, description="Optional specific recipient user ID")
    expires_in_hours: int | None = Field(None, ge=1, le=8760, description="Optional expiration window in hours")


class ProofShareResponse(BaseModel):
    """
    Public representation of a verification share.
    Only exposes public commitments and authorization metadata.
    Never exposes raw SBOM components, private dependencies, or internal paths.
    """
    id: UUID4
    proof_job_id: UUID4
    vendor_id: UUID4
    share_token: str
    recipient_role: str
    recipient_user_id: UUID4 | None = None
    is_revoked: bool = False
    revoked_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime
    is_active: bool = True
    # Public commitments for convenience of the buyer
    sbom_root: str | None = None
    vulnerability_db_root: str | None = None
    policy_hash: str | None = None

    model_config = ConfigDict(from_attributes=True)


class DeleteProofShareResponse(BaseModel):
    """
    Response acknowledging deletion of a revoked verification share.
    """
    status: str = "deleted"
    id: UUID4
    message: str = "Revoked proof share successfully deleted"
