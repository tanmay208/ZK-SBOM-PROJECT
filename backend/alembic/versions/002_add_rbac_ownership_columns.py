"""add rbac ownership columns and fix foreign keys

Revision ID: 002_rbac
Revises: 001_initial
Create Date: 2026-09-14

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql


# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add user_id / created_by to tables
    op.add_column("applications", sa.Column("user_id", sa.Uuid(), nullable=True), schema="sbom")
    op.add_column("sbom_uploads", sa.Column("user_id", sa.Uuid(), nullable=True), schema="sbom")
    op.add_column("vulnerability_snapshots", sa.Column("created_by", sa.Uuid(), nullable=True), schema="vulnerability")
    op.add_column("proof_jobs", sa.Column("user_id", sa.Uuid(), nullable=True), schema="zkp")
    op.add_column("verification_requests", sa.Column("user_id", sa.Uuid(), nullable=True), schema="verification")

    # Add missing inter-schema foreign keys
    op.create_foreign_key(
        "fk_proof_jobs_sbom_upload_id",
        "proof_jobs", "sbom_uploads",
        ["sbom_upload_id"], ["id"],
        source_schema="zkp", referent_schema="sbom", ondelete="CASCADE"
    )
    op.create_foreign_key(
        "fk_proof_jobs_snapshot_id",
        "proof_jobs", "vulnerability_snapshots",
        ["snapshot_id"], ["id"],
        source_schema="zkp", referent_schema="vulnerability", ondelete="CASCADE"
    )
    op.create_foreign_key(
        "fk_proof_jobs_policy_id",
        "proof_jobs", "security_policies",
        ["policy_id"], ["id"],
        source_schema="zkp", referent_schema="policy", ondelete="CASCADE"
    )
    op.create_foreign_key(
        "fk_verification_certificates_verification_request_id",
        "verification_certificates", "verification_requests",
        ["verification_request_id"], ["id"],
        source_schema="verification", referent_schema="verification", ondelete="CASCADE"
    )
    op.create_foreign_key(
        "fk_scan_results_sbom_upload_id",
        "scan_results", "sbom_uploads",
        ["sbom_upload_id"], ["id"],
        source_schema="vulnerability", referent_schema="sbom", ondelete="CASCADE"
    )


def downgrade() -> None:
    # Drop missing inter-schema foreign keys
    op.drop_constraint("fk_scan_results_sbom_upload_id", "scan_results", schema="vulnerability", type_="foreignkey")
    op.drop_constraint("fk_verification_certificates_verification_request_id", "verification_certificates", schema="verification", type_="foreignkey")
    op.drop_constraint("fk_proof_jobs_policy_id", "proof_jobs", schema="zkp", type_="foreignkey")
    op.drop_constraint("fk_proof_jobs_snapshot_id", "proof_jobs", schema="zkp", type_="foreignkey")
    op.drop_constraint("fk_proof_jobs_sbom_upload_id", "proof_jobs", schema="zkp", type_="foreignkey")

    # Drop user_id / created_by from tables
    op.drop_column("verification_requests", "user_id", schema="verification")
    op.drop_column("proof_jobs", "user_id", schema="zkp")
    op.drop_column("vulnerability_snapshots", "created_by", schema="vulnerability")
    op.drop_column("sbom_uploads", "user_id", schema="sbom")
    op.drop_column("applications", "user_id", schema="sbom")
