"""enforce application tenant isolation via unique constraint

AUD-A-001 remediation: add a UNIQUE constraint on (name, vendor, user_id)
in the sbom.applications table so the database enforces that each user
owns their own application record for a given name/vendor pair.

Revision ID: 014
Revises: 013
Create Date: 2026-10-11

"""

from alembic import op

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_sbom_applications_name_vendor_user",
        "applications",
        ["name", "vendor", "user_id"],
        schema="sbom",
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_sbom_applications_name_vendor_user",
        "applications",
        schema="sbom",
        type_="unique",
    )
