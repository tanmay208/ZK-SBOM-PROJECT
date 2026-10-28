"""restore ORM-declared constraints and metadata missing from PostgreSQL

Revision ID: 011
Revises: 010
Create Date: 2026-10-03

"""

from alembic import op
import sqlalchemy as sa


revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The current database contains a small number of nullable owner columns
    # pointing at User rows that no longer exist. Match the ORM's SET NULL
    # delete semantics without deleting any owning records.
    op.execute(
        """UPDATE sbom.applications AS child
           SET user_id = NULL
           WHERE child.user_id IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM public.users AS parent WHERE parent.id = child.user_id)"""
    )
    op.execute(
        """UPDATE vulnerability.vulnerability_snapshots AS child
           SET created_by = NULL
           WHERE child.created_by IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM public.users AS parent WHERE parent.id = child.created_by)"""
    )
    op.execute(
        """UPDATE zkp.proof_jobs AS child
           SET user_id = NULL
           WHERE child.user_id IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM public.users AS parent WHERE parent.id = child.user_id)"""
    )

    # Preserve all rows. PostgreSQL validates each new constraint as it is
    # added; the migration does not delete application records.
    op.create_index(
        "ix_sbom_applications_user_id",
        "applications",
        ["user_id"],
        schema="sbom",
    )

    op.create_foreign_key(
        "applications_user_id_fkey",
        "applications",
        "users",
        ["user_id"],
        ["id"],
        source_schema="sbom",
        referent_schema="public",
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "verification_requests_proof_job_id_fkey",
        "verification_requests",
        "proof_jobs",
        ["proof_job_id"],
        ["id"],
        source_schema="verification",
        referent_schema="zkp",
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "verification_requests_user_id_fkey",
        "verification_requests",
        "users",
        ["user_id"],
        ["id"],
        source_schema="verification",
        referent_schema="public",
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "vulnerability_snapshots_created_by_fkey",
        "vulnerability_snapshots",
        "users",
        ["created_by"],
        ["id"],
        source_schema="vulnerability",
        referent_schema="public",
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "chunk_proof_sets_proof_job_id_fkey",
        "chunk_proof_sets",
        "proof_jobs",
        ["proof_job_id"],
        ["id"],
        source_schema="zkp",
        referent_schema="zkp",
    )
    op.create_foreign_key(
        "segment_proofs_chunk_id_fkey",
        "segment_proofs",
        "chunk_proof_sets",
        ["chunk_id"],
        ["id"],
        source_schema="zkp",
        referent_schema="zkp",
    )
    op.create_foreign_key(
        "proof_jobs_user_id_fkey",
        "proof_jobs",
        "users",
        ["user_id"],
        ["id"],
        source_schema="zkp",
        referent_schema="public",
        ondelete="SET NULL",
    )

    op.create_unique_constraint(
        "uq_vuln_mapping_snapshot_comp",
        "component_vulnerability_mappings",
        ["snapshot_id", "component_hash"],
        schema="vulnerability",
    )

    op.alter_column(
        "security_policies",
        "max_allowed_cvss_int",
        existing_type=sa.Integer(),
        comment="Integer representation for ZKP circuit (e.g. 7.5 -> 75)",
        schema="policy",
    )


def downgrade() -> None:
    op.alter_column(
        "security_policies",
        "max_allowed_cvss_int",
        existing_type=sa.Integer(),
        comment=None,
        schema="policy",
    )
    op.drop_constraint(
        "uq_vuln_mapping_snapshot_comp",
        "component_vulnerability_mappings",
        schema="vulnerability",
        type_="unique",
    )
    op.drop_constraint(
        "proof_jobs_user_id_fkey",
        "proof_jobs",
        schema="zkp",
        type_="foreignkey",
    )
    op.drop_constraint(
        "segment_proofs_chunk_id_fkey",
        "segment_proofs",
        schema="zkp",
        type_="foreignkey",
    )
    op.drop_constraint(
        "chunk_proof_sets_proof_job_id_fkey",
        "chunk_proof_sets",
        schema="zkp",
        type_="foreignkey",
    )
    op.drop_constraint(
        "vulnerability_snapshots_created_by_fkey",
        "vulnerability_snapshots",
        schema="vulnerability",
        type_="foreignkey",
    )
    op.drop_constraint(
        "verification_requests_user_id_fkey",
        "verification_requests",
        schema="verification",
        type_="foreignkey",
    )
    op.drop_constraint(
        "verification_requests_proof_job_id_fkey",
        "verification_requests",
        schema="verification",
        type_="foreignkey",
    )
    op.drop_constraint(
        "applications_user_id_fkey",
        "applications",
        schema="sbom",
        type_="foreignkey",
    )
    op.drop_index(
        "ix_sbom_applications_user_id",
        table_name="applications",
        schema="sbom",
    )
