"""One-shot PostgreSQL idempotency acceptance probe.

This writes uniquely identified temporary records to the configured database,
submits ten concurrent identical service requests with cryptographic execution
stubbed, asserts one canonical request and certificate, then removes its rows.
It is deliberately not run by pytest collection.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))
load_dotenv(PROJECT_ROOT / ".env", override=False)

from shared.config import get_db_settings  # noqa: E402
from shared.models.user import User  # noqa: E402
from policy_service.app.models.policy_models import SecurityPolicy  # noqa: E402
from sbom_service.app.models.sbom_models import Application, SBOMUpload  # noqa: E402
from verification_service.app.models.verification_models import (  # noqa: E402
    VerificationCertificate,
    VerificationRequest,
)
from verification_service.app.schemas.verification_schemas import (  # noqa: E402
    VerifyProofRequest,
)
from verification_service.app.services.verification_service import (  # noqa: E402
    VerificationService,
)
from vulnerability_service.app.models.vulnerability_models import (  # noqa: E402
    VulnerabilitySnapshot,
)
from zkp_service.app.models.zkp_models import ProofJob  # noqa: E402


WORKERS = 10


class AcceptanceVerifier:
    """Stub only the expensive cryptographic verifier, not DB concurrency."""

    def verify(self, proof_job_id, session=None, **kwargs) -> str:
        time.sleep(1)
        return "verified"


def _assert_postgresql(engine) -> None:
    if engine.dialect.name != "postgresql":
        raise RuntimeError("Concurrency acceptance requires PostgreSQL")
    with engine.connect() as conn:
        version = conn.execute(text("SHOW server_version")).scalar_one()
        required = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conname IN "
                    "('uq_verification_request_idempotency', 'uq_cert_per_request')"
                )
            )
        }
    if required != {
        "uq_verification_request_idempotency",
        "uq_cert_per_request",
    }:
        raise RuntimeError("Required PostgreSQL idempotency constraints are absent")
    print(f"PostgreSQL {version}; required uniqueness constraints present")


def run_concurrent_requests() -> None:
    settings = get_db_settings()
    signing_secret = os.environ.get("CERTIFICATE_SECRET_KEY", "")
    if not signing_secret:
        raise RuntimeError("CERTIFICATE_SECRET_KEY must be configured")

    engine = create_engine(settings.url, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    user_id = uuid.uuid4()
    app_id = uuid.uuid4()
    sbom_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    job_id = uuid.uuid4()
    sbom_root = "0x" + "a" * 64
    vuln_root = "0x" + "b" * 64
    policy_hash = "0x" + "c" * 64
    request = VerifyProofRequest(
        sbom_root=sbom_root,
        vulnerability_db_root=vuln_root,
        policy_hash=policy_hash,
        proof_job_id=job_id,
    )

    try:
        _assert_postgresql(engine)

        # Commit shared authoritative inputs before worker sessions start.
        with SessionLocal.begin() as db:
            db.add(
                User(
                    id=user_id,
                    username=f"stage21n-concurrency-{user_id.hex}",
                    hashed_password="acceptance-probe",
                    role="vendor",
                )
            )
            # The shared Base has no ORM relationship from Application to
            # User, so explicitly persist the FK target before its dependents.
            db.flush()
            db.add(
                Application(
                    id=app_id,
                    name=f"Stage21N {app_id.hex}",
                    vendor="acceptance-probe",
                    user_id=user_id,
                )
            )
            db.flush()
            db.add(
                SBOMUpload(
                    id=sbom_id,
                    application_id=app_id,
                    user_id=user_id,
                    filename="acceptance.json",
                    spec_version="1.4",
                    sbom_root=sbom_root,
                    status="committed",
                )
            )
            db.add(
                VulnerabilitySnapshot(
                    id=snapshot_id,
                    snapshot_label=f"Stage21N {snapshot_id.hex}",
                    provisional_smt_root=vuln_root,
                    authoritative_smt_root=vuln_root,
                    status="frozen",
                )
            )
            db.add(
                SecurityPolicy(
                    id=policy_id,
                    name=f"Stage21N {policy_id.hex}",
                    max_allowed_cvss=10.0,
                    max_allowed_cvss_int=10,
                    policy_hash=policy_hash,
                    is_active=1,
                )
            )
            db.flush()
            db.add(
                ProofJob(
                    id=job_id,
                    user_id=user_id,
                    sbom_upload_id=sbom_id,
                    snapshot_id=snapshot_id,
                    policy_id=policy_id,
                    created_at=datetime.now(timezone.utc),
                )
            )

        def submit_once():
            with SessionLocal() as session:
                result = VerificationService(
                    session, verifier=AcceptanceVerifier()
                ).process_verification(request, user_id)
                return result.id, result.result

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = [pool.submit(submit_once) for _ in range(WORKERS)]
            results = [future.result() for future in futures]

        with SessionLocal() as db:
            requests = (
                db.query(VerificationRequest)
                .filter(VerificationRequest.user_id == user_id)
                .all()
            )
            certificates = (
                db.query(VerificationCertificate)
                .join(VerificationRequest)
                .filter(VerificationRequest.user_id == user_id)
                .all()
            )

        result_ids = {result_id for result_id, result in results}
        if (
            len(results) != WORKERS
            or any(result != "verified" for _, result in results)
            or len(result_ids) != 1
            or len(requests) != 1
            or len(certificates) != 1
            or certificates[0].verification_request_id != requests[0].id
        ):
            raise AssertionError(
                "PostgreSQL concurrency acceptance failed: expected "
                f"{WORKERS} successful responses to one request and one certificate; "
                f"observed responses={len(results)}, request_rows={len(requests)}, "
                f"certificate_rows={len(certificates)}"
            )

        print(
            f"PASS: {WORKERS} concurrent identical requests converged to "
            "1 VerificationRequest and 1 Certificate"
        )
    finally:
        # Remove only rows carrying this run's unique identifiers.
        with SessionLocal.begin() as db:
            db.query(VerificationCertificate).filter(
                VerificationCertificate.verification_request_id.in_(
                    db.query(VerificationRequest.id).filter(
                        VerificationRequest.user_id == user_id
                    )
                )
            ).delete(synchronize_session=False)
            db.query(VerificationRequest).filter(
                VerificationRequest.user_id == user_id
            ).delete(synchronize_session=False)
            db.query(ProofJob).filter(ProofJob.id == job_id).delete(
                synchronize_session=False
            )
            db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).delete(
                synchronize_session=False
            )
            db.query(VulnerabilitySnapshot).filter(
                VulnerabilitySnapshot.id == snapshot_id
            ).delete(synchronize_session=False)
            db.query(SBOMUpload).filter(SBOMUpload.id == sbom_id).delete(
                synchronize_session=False
            )
            db.query(Application).filter(Application.id == app_id).delete(
                synchronize_session=False
            )
            db.query(User).filter(User.id == user_id).delete(
                synchronize_session=False
            )
        engine.dispose()


if __name__ == "__main__":
    run_concurrent_requests()
