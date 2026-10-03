"""allow unavailable verification records without a proof job

Revision ID: 010
Revises: 009
Create Date: 2026-10-03

"""
from alembic import op


revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The API accepts legacy requests without a proof_job_id so that missing
    # and foreign jobs have the same persisted anti-enumeration result.
    op.alter_column(
        "verification_requests",
        "proof_job_id",
        nullable=True,
        schema="verification",
    )


def downgrade() -> None:
    op.alter_column(
        "verification_requests",
        "proof_job_id",
        nullable=False,
        schema="verification",
    )
