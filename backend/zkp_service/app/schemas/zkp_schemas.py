from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.types import UUID4


class GenerateProofRequest(BaseModel):
    """
    Request model to generate a zero-knowledge proof.
    Takes references to existing authoritative artifacts across boundaries.
    """
    sbom_upload_id: UUID4 = Field(..., description="ID of the committed SBOM upload")
    snapshot_id: UUID4 = Field(..., description="ID of the vulnerability intelligence snapshot")
    policy_id: UUID4 = Field(..., description="ID of the policy to verify against")


class SegmentProofResponse(BaseModel):
    id: UUID4
    chunk_id: UUID4
    chunk_index: int
    total_chunks: int
    segment_index: int
    
    proof_artifact: str | None = None
    proof_artifact_hash: str | None = None
    
    components_commit: str | None = None
    hash_in_commit: str | None = None
    hash_out_commit: str | None = None
    
    global_sbom_root: str | None = None
    vulnerability_db_root: str | None = None
    policy_hash: str | None = None
    
    status: str
    created_at: datetime
    completed_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ChunkProofSetResponse(BaseModel):
    id: UUID4
    proof_job_id: UUID4
    chunk_index: int
    total_chunks: int
    component_start: int
    component_count: int
    components_commit: str | None = None
    status: str
    created_at: datetime
    
    segments: list[SegmentProofResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ProofJobResponse(BaseModel):
    """
    Response model detailing the status and public artifacts of a proof job.
    CRITICAL: Never expose private component hashes, versions, or scores here.
    """
    id: UUID4
    sbom_upload_id: UUID4
    snapshot_id: UUID4
    policy_id: UUID4
    
    status: str
    
    # Public Commitments
    sbom_root: str | None = None
    vulnerability_db_root: str | None = None
    policy_hash: str | None = None
    
    # Execution Artifacts
    proof_artifact: str | None = None
    proof_archive_hash: str | None = None
    error_message: str | None = None
    
    created_at: datetime
    completed_at: datetime | None = None
    
    chunks: list[ChunkProofSetResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)

    @field_validator("error_message", mode="before")
    @classmethod
    def sanitize_error_message(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return "Proof generation failed"
