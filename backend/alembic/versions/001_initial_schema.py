"""initial schema - five logical schemas per DATABASE_SCHEMA.md

Revision ID: 001_initial
Revises: None
Create Date: 2026-09-03

Creates the five logical SQL schemas and all foundational tables:
  sbom:           applications, sbom_uploads, components
  vulnerability:  vulnerability_records, vulnerability_snapshots,
                  component_vulnerability_mappings, scan_results
  policy:         security_policies
  zkp:            proof_jobs
  verification:   verification_requests, verification_certificates
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

# revision identifiers
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -----------------------------------------------------------------
    # SQL schemas (idempotent — env.py also creates them, but belt-and-braces)
    # -----------------------------------------------------------------
    for schema in ("sbom", "vulnerability", "policy", "zkp", "verification"):
        op.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')

    # =================================================================
    # SBOM SCHEMA
    # =================================================================
    op.create_table(
        "applications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("vendor", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        schema="sbom",
    )
    op.create_index("ix_sbom_applications_vendor", "applications", ["vendor"], schema="sbom")

    op.create_table(
        "sbom_uploads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(512), nullable=True),
        sa.Column("format", sa.String(50), nullable=False, server_default="CycloneDX"),
        sa.Column("spec_version", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("sbom_root", sa.String(128), nullable=True),
        sa.Column("component_count", sa.Integer(), nullable=True),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["application_id"], ["sbom.applications.id"], ondelete="CASCADE"),
        schema="sbom",
    )
    op.create_index("ix_sbom_uploads_application_id", "sbom_uploads", ["application_id"], schema="sbom")
    op.create_index("ix_sbom_uploads_status", "sbom_uploads", ["status"], schema="sbom")

    op.create_table(
        "components",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sbom_upload_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("purl", sa.String(1024), nullable=True),
        sa.Column("purl_canonical", sa.String(1024), nullable=True),
        sa.Column("component_hash", sa.String(128), nullable=True),
        sa.Column("position", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["sbom_upload_id"], ["sbom.sbom_uploads.id"], ondelete="CASCADE"),
        schema="sbom",
    )
    op.create_index("ix_sbom_components_sbom_upload_id", "components", ["sbom_upload_id"], schema="sbom")
    op.create_index("ix_sbom_components_purl", "components", ["purl"], schema="sbom")

    # =================================================================
    # VULNERABILITY SCHEMA
    # =================================================================
    op.create_table(
        "vulnerability_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_base_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(255), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("published_date", sa.DateTime(), nullable=True),
        sa.Column("modified_date", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(50), nullable=False, server_default="NVD"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
        schema="vulnerability",
    )
    op.create_index("ix_vuln_records_cve_id", "vulnerability_records", ["cve_id"], schema="vulnerability")
    op.create_index("ix_vuln_records_severity", "vulnerability_records", ["severity"], schema="vulnerability")

    op.create_table(
        "vulnerability_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_label", sa.String(255), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("provisional_smt_root", sa.String(128), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        schema="vulnerability",
    )
    op.create_index("ix_vuln_snapshots_status", "vulnerability_snapshots", ["status"], schema="vulnerability")

    op.create_table(
        "component_vulnerability_mappings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("component_hash", sa.String(128), nullable=False),
        sa.Column("max_cvss", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cve_ids", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["vulnerability.vulnerability_snapshots.id"], ondelete="CASCADE"),
        schema="vulnerability",
    )
    op.create_index("ix_vuln_mappings_snapshot_id", "component_vulnerability_mappings", ["snapshot_id"], schema="vulnerability")
    op.create_index("ix_vuln_mappings_component_hash", "component_vulnerability_mappings", ["component_hash"], schema="vulnerability")

    op.create_table(
        "scan_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sbom_upload_id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("component_name", sa.String(512), nullable=False),
        sa.Column("component_version", sa.String(128), nullable=True),
        sa.Column("component_purl", sa.String(1024), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("fix_available", sa.String(10), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        schema="vulnerability",
    )
    op.create_index("ix_vuln_scan_results_sbom_upload_id", "scan_results", ["sbom_upload_id"], schema="vulnerability")

    # =================================================================
    # POLICY SCHEMA
    # =================================================================
    op.create_table(
        "security_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("max_allowed_cvss", sa.Float(), nullable=False),
        sa.Column("max_allowed_cvss_int", sa.Integer(), nullable=False),
        sa.Column("policy_hash", sa.String(128), nullable=True),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        schema="policy",
    )

    # =================================================================
    # ZKP SCHEMA
    # =================================================================
    op.create_table(
        "proof_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sbom_upload_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("sbom_root", sa.String(128), nullable=True),
        sa.Column("vulnerability_db_root", sa.String(128), nullable=True),
        sa.Column("policy_hash", sa.String(128), nullable=True),
        sa.Column("proof_artifact", sa.Text(), nullable=True),
        sa.Column("error_message", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema="zkp",
    )

    # =================================================================
    # VERIFICATION SCHEMA
    # =================================================================
    op.create_table(
        "verification_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sbom_root", sa.String(128), nullable=False),
        sa.Column("vulnerability_db_root", sa.String(128), nullable=False),
        sa.Column("policy_hash", sa.String(128), nullable=False),
        sa.Column("proof_artifact", sa.Text(), nullable=False),
        sa.Column("result", sa.String(20), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        schema="verification",
    )

    op.create_table(
        "verification_certificates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("verification_request_id", sa.Uuid(), nullable=False),
        sa.Column("certificate_data", sa.Text(), nullable=False),
        sa.Column("sbom_root", sa.String(128), nullable=False),
        sa.Column("vulnerability_db_root", sa.String(128), nullable=False),
        sa.Column("policy_hash", sa.String(128), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        schema="verification",
    )


def downgrade() -> None:
    # Drop tables in reverse order of creation (dependencies first)
    op.drop_table("verification_certificates", schema="verification")
    op.drop_table("verification_requests", schema="verification")
    op.drop_table("proof_jobs", schema="zkp")
    op.drop_table("security_policies", schema="policy")
    op.drop_table("scan_results", schema="vulnerability")
    op.drop_table("component_vulnerability_mappings", schema="vulnerability")
    op.drop_table("vulnerability_snapshots", schema="vulnerability")
    op.drop_table("vulnerability_records", schema="vulnerability")
    op.drop_table("components", schema="sbom")
    op.drop_table("sbom_uploads", schema="sbom")
    op.drop_table("applications", schema="sbom")

    # Drop schemas
    for schema in ("verification", "zkp", "policy", "vulnerability", "sbom"):
        op.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
