"""auth lifecycle and revocation schema updates

Revision ID: 015
Revises: 014
Create Date: 2026-10-18

Schema Updates:
1. public.users:
   - Preflight check: Rejects unexpected legacy roles (fails closed).
   - chk_users_role: Check constraint enforcing approved 5 roles (vendor, buyer, auditor, admin, trusted_importer).
   - is_active: BOOLEAN NOT NULL DEFAULT TRUE (account deactivation support).
   - updated_at: TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP (mutation tracking).
2. sbom.applications:
   - is_active: BOOLEAN NOT NULL DEFAULT TRUE (soft archival support).
   - archived_at: TIMESTAMP WITH TIME ZONE NULL (archival timestamp).
   - chk_sbom_applications_archival: Consistency check ensuring (is_active=TRUE AND archived_at IS NULL)
     OR (is_active=FALSE AND archived_at IS NOT NULL).
   - ix_sbom_applications_user_active: Partial composite index on (user_id, is_active).
3. verification.verification_certificates:
   - revoked_by: UUID NULL (actor attribution for certificate revocation).
   - fk_verification_certificates_revoked_by: Foreign key to public.users(id) ON DELETE SET NULL.
   - ix_verification_certificates_revoked_by: Index on revoked_by WHERE revoked_by IS NOT NULL.
   - chk_certificate_revocation_state: Replacement check constraint harmonizing revocation state
     to permit historical revoked certificates (revoked_by IS NULL) and deleted revoking users,
     while strictly requiring (revoked_at IS NOT NULL) when is_revoked=TRUE, and
     (revoked_at IS NULL AND revoked_by IS NULL) when is_revoked=FALSE.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "015"
down_revision: Union[str, None] = "014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ALLOWED_ROLES = ("vendor", "buyer", "auditor", "admin", "trusted_importer")


def upgrade() -> None:
    # -----------------------------------------------------------------
    # 1. public.users: Preflight Role Verification
    # -----------------------------------------------------------------
    conn = op.get_bind()
    # Check for any unexpected legacy roles before applying the check constraint.
    # Silent rewriting or defaulting of unexpected roles is strictly forbidden.
    res = conn.execute(
        sa.text(
            "SELECT DISTINCT role FROM public.users "
            "WHERE role NOT IN ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer')"
        )
    )
    unexpected = [row[0] for row in res.fetchall()]
    if unexpected:
        raise Exception(
            f"Migration 015 aborted: unexpected legacy role(s) detected in public.users: {unexpected}. "
            f"Allowed roles are: {sorted(ALLOWED_ROLES)}. Silent role rewriting is prohibited. "
            "Manual owner review and data normalization required."
        )

    # -----------------------------------------------------------------
    # 2. public.users: Role Constraint & Lifecycle Columns
    # -----------------------------------------------------------------
    op.create_check_constraint(
        "chk_users_role",
        "users",
        "role IN ('vendor', 'buyer', 'auditor', 'admin', 'trusted_importer')",
        schema="public",
    )
    op.add_column(
        "users",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        schema="public",
    )
    op.add_column(
        "users",
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        schema="public",
    )

    # -----------------------------------------------------------------
    # 3. sbom.applications: Soft Archival & Deletion Safeguard
    # -----------------------------------------------------------------
    op.add_column(
        "applications",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        schema="sbom",
    )
    op.add_column(
        "applications",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        schema="sbom",
    )
    op.create_check_constraint(
        "chk_sbom_applications_archival",
        "applications",
        "(is_active = TRUE AND archived_at IS NULL) OR "
        "(is_active = FALSE AND archived_at IS NOT NULL)",
        schema="sbom",
    )
    op.create_index(
        "ix_sbom_applications_user_active",
        "applications",
        ["user_id", "is_active"],
        schema="sbom",
    )

    # -----------------------------------------------------------------
    # 4. verification.verification_certificates: Revocation Attribution
    # -----------------------------------------------------------------
    op.add_column(
        "verification_certificates",
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        schema="verification",
    )
    op.create_foreign_key(
        "fk_verification_certificates_revoked_by",
        "verification_certificates",
        "users",
        ["revoked_by"],
        ["id"],
        source_schema="verification",
        referent_schema="public",
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_verification_certificates_revoked_by",
        "verification_certificates",
        ["revoked_by"],
        schema="verification",
        postgresql_where=sa.text("revoked_by IS NOT NULL"),
    )

    # Harmonize check constraint chk_certificate_revocation_state:
    # Drop existing constraint from migration 009
    op.drop_constraint(
        "chk_certificate_revocation_state",
        "verification_certificates",
        schema="verification",
        type_="check",
    )
    # Re-create with state consistency for revoked_by:
    # - If active (is_revoked=FALSE): revoked_at and revoked_by MUST be NULL.
    # - If revoked (is_revoked=TRUE): revoked_at MUST be NOT NULL; revoked_by may be NULL
    #   (preserving historical rows revoked prior to 015 and users deleted via ON DELETE SET NULL).
    op.create_check_constraint(
        "chk_certificate_revocation_state",
        "verification_certificates",
        "(is_revoked = FALSE AND revoked_at IS NULL AND revoked_by IS NULL) OR "
        "(is_revoked = TRUE AND revoked_at IS NOT NULL)",
        schema="verification",
    )


def downgrade() -> None:
    # -----------------------------------------------------------------
    # 1. verification.verification_certificates: Revert Revocation
    # -----------------------------------------------------------------
    op.drop_constraint(
        "chk_certificate_revocation_state",
        "verification_certificates",
        schema="verification",
        type_="check",
    )
    # Restore migration 009 constraint
    op.create_check_constraint(
        "chk_certificate_revocation_state",
        "verification_certificates",
        "(is_revoked = FALSE AND revoked_at IS NULL) OR "
        "(is_revoked = TRUE AND revoked_at IS NOT NULL)",
        schema="verification",
    )
    op.drop_index(
        "ix_verification_certificates_revoked_by",
        table_name="verification_certificates",
        schema="verification",
    )
    op.drop_constraint(
        "fk_verification_certificates_revoked_by",
        "verification_certificates",
        schema="verification",
        type_="foreignkey",
    )
    op.drop_column("verification_certificates", "revoked_by", schema="verification")

    # -----------------------------------------------------------------
    # 2. sbom.applications: Revert Archival Columns
    # -----------------------------------------------------------------
    op.drop_index(
        "ix_sbom_applications_user_active",
        table_name="applications",
        schema="sbom",
    )
    op.drop_constraint(
        "chk_sbom_applications_archival",
        "applications",
        schema="sbom",
        type_="check",
    )
    op.drop_column("applications", "archived_at", schema="sbom")
    op.drop_column("applications", "is_active", schema="sbom")

    # -----------------------------------------------------------------
    # 3. public.users: Revert Lifecycle Columns & Constraint
    # -----------------------------------------------------------------
    op.drop_column("users", "updated_at", schema="public")
    op.drop_column("users", "is_active", schema="public")
    op.drop_constraint("chk_users_role", "users", schema="public", type_="check")
