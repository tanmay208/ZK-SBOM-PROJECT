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

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode='after')
    def mask_if_revoked(self) -> 'VerificationCertificateResponse':
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

