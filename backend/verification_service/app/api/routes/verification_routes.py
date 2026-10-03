from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from pydantic import ValidationError

from shared.database import get_session
from verification_service.app.schemas.verification_schemas import (
    VerifyProofRequest,
    VerificationResponse,
    VerificationCertificateResponse,
    RevokeCertificateRequest,
)
from verification_service.app.services.verification_service import VerificationService
from shared.auth import get_current_user
from shared.models.user import User


router = APIRouter(prefix="/api/v1/verification", tags=["verification"])


@router.post(
    "/verify",
    response_model=VerificationResponse,
    openapi_extra={
        "requestBody": {
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "sbom_root": {"type": "string"},
                            "vulnerability_db_root": {"type": "string"},
                            "policy_hash": {"type": "string"},
                            "proof_job_id": {"type": "string", "format": "uuid"},
                            "proof_artifact": {"type": "string", "format": "binary"}
                        },
                        "required": ["sbom_root", "vulnerability_db_root", "policy_hash"]
                    }
                },
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/VerifyProofRequest"
                    }
                }
            },
            "required": True
        }
    }
)
async def verify_proof(
    request: Request,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Submit a proof artifact and its corresponding public commitments for verification.
    Accepts both application/json (legacy) and multipart/form-data.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        try:
            req_data = VerifyProofRequest(**body)
        except ValidationError as e:
            from fastapi.exceptions import RequestValidationError
            raise RequestValidationError(e.errors())
    elif "multipart/form-data" in content_type:
        form = await request.form()
        data = {
            "sbom_root": form.get("sbom_root"),
            "vulnerability_db_root": form.get("vulnerability_db_root"),
            "policy_hash": form.get("policy_hash")
        }
        if "proof_job_id" in form:
            data["proof_job_id"] = form.get("proof_job_id")
            
        artifact = form.get("proof_artifact")
        if artifact is not None:
            if hasattr(artifact, "read"):
                data["proof_artifact"] = (await artifact.read()).decode("utf-8")
            else:
                data["proof_artifact"] = artifact
                
        try:
            req_data = VerifyProofRequest(**data)
        except ValidationError as e:
            from fastapi.exceptions import RequestValidationError
            raise RequestValidationError(e.errors())
    else:
        raise HTTPException(status_code=415, detail="Unsupported media type")

    service = VerificationService(db)
    req_record = service.process_verification(req_data, user_id=current_user.id)
    
    cert_record = None
    if req_record.result == "verified":
        cert_record = service.get_certificate_by_request(req_record.id, user_id=current_user.id)
        
    return VerificationResponse(
        id=req_record.id,
        sbom_root=req_record.sbom_root,
        vulnerability_db_root=req_record.vulnerability_db_root,
        policy_hash=req_record.policy_hash,
        result=req_record.result,
        verified_at=req_record.verified_at,
        created_at=req_record.created_at,
        certificate=VerificationCertificateResponse.model_validate(cert_record) if cert_record else None
    )


from typing import List
from shared.auth import get_current_user
from shared.models.user import User
from verification_service.app.models.verification_models import VerificationCertificate


@router.get("/certificates", response_model=List[VerificationCertificateResponse])
def list_certificates(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    from zkp_service.app.models.zkp_models import ProofJob
    from verification_service.app.models.verification_models import VerificationRequest
    
    certs = (
        db.query(VerificationCertificate)
        .join(VerificationRequest, VerificationRequest.id == VerificationCertificate.verification_request_id)
        .join(ProofJob, ProofJob.id == VerificationRequest.proof_job_id)
        .filter(VerificationRequest.user_id == current_user.id)
        .order_by(VerificationCertificate.issued_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return certs

@router.get("/certificates/{certificate_id}", response_model=VerificationCertificateResponse)
def get_certificate(
    certificate_id: UUID, 
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve public verification certificate metadata by its unguessable ID.
    Enforces IDOR protection by checking owner.
    """
    service = VerificationService(db)
    cert = service.get_certificate(certificate_id, user_id=current_user.id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    
    return cert

@router.post("/certificates/{certificate_id}/revoke", response_model=VerificationCertificateResponse)
def revoke_certificate(
    certificate_id: UUID,
    request: RevokeCertificateRequest,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    """
    Revoke a verification certificate.
    Enforces IDOR protection by checking owner.
    """
    service = VerificationService(db)
    cert = service.revoke_certificate(certificate_id, user_id=current_user.id, reason=request.reason)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found or unauthorized")
        
    return cert


@router.get("/certificates/{certificate_id}/validate")
def validate_certificate(
    certificate_id: UUID,
    db: Session = Depends(get_session),
):
    """
    Authoritative certificate validation endpoint.

    Returns whether a certificate is currently accepted as valid.
    A revoked certificate is NEVER accepted as currently valid,
    even if the underlying JWT would still pass signature verification.

    This endpoint is intentionally unauthenticated — any party holding
    a certificate ID may check its validity (certificate IDs are UUIDv4,
    making enumeration infeasible).
    """
    service = VerificationService(db)
    result = service.validate_certificate(certificate_id)
    status_code = 200 if result["valid"] else 200  # always 200, validity in body
    return result


from pydantic import BaseModel as _BaseModel


class ValidateTokenRequest(_BaseModel):
    token: str


@router.post("/certificates/validate-token")
def validate_certificate_token(
    request: ValidateTokenRequest,
    db: Session = Depends(get_session),
):
    """
    Validate a previously-issued JWT certificate token against the
    authoritative revocation state.

    Even if the JWT signature is cryptographically valid, this endpoint
    rejects tokens whose corresponding certificate has been revoked.
    This prevents previously-copied certificate material from bypassing
    the application's authoritative revocation state.
    """
    service = VerificationService(db)
    return service.validate_certificate_token(request.token)

