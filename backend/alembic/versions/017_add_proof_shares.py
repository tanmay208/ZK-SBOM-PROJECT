"""add proof shares table for vendor-to-buyer verification

Revision ID: 017
Revises: 016
Create Date: 2026-10-29

Schema Updates:
verification.proof_shares:
  - id: UUID PK
  - proof_job_id: UUID FK -> zkp.proof_jobs.id (ON DELETE CASCADE)
  - vendor_id: UUID FK -> public.users.id (ON DELETE CASCADE)
  - share_token: VARCHAR(64) UNIQUE NOT NULL
  - recipient_role: VARCHAR(20) NOT NULL DEFAULT 'buyer'
  - recipient_user_id: UUID FK -> public.users.id (ON DELETE SET NULL, NULLABLE)
  - is_revoked: BOOLEAN NOT NULL DEFAULT FALSE
  - revoked_at: TIMESTAMP WITH TIME ZONE NULL
  - expires_at: TIMESTAMP WITH TIME ZONE NULL
  - created_at: TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "017"
down_revision: Union[str, None] = "016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "proof_shares",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("proof_job_id", sa.Uuid(), nullable=False),
        sa.Column("vendor_id", sa.Uuid(), nullable=False),
        sa.Column("share_token", sa.String(64), nullable=False),
        sa.Column("recipient_role", sa.String(20), nullable=False, server_default="buyer"),
        sa.Column("recipient_user_id", sa.Uuid(), nullable=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["proof_job_id"],
            ["zkp.proof_jobs.id"],
            name="fk_proof_shares_proof_job_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["vendor_id"],
            ["public.users.id"],
            name="fk_proof_shares_vendor_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"],
            ["public.users.id"],
            name="fk_proof_shares_recipient_user_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("share_token", name="uq_verification_proof_shares_token"),
        sa.CheckConstraint(
            "(is_revoked = false AND revoked_at IS NULL) OR "
            "(is_revoked = true AND revoked_at IS NOT NULL)",
            name="chk_proof_share_revocation_state",
        ),
        schema="verification",
    )
    op.create_index(
        "ix_verification_proof_shares_token",
        "proof_shares",
        ["share_token"],
        schema="verification",
    )
    op.create_index(
        "ix_verification_proof_shares_proof_job_id",
        "proof_shares",
        ["proof_job_id"],
        schema="verification",
    )
    op.create_index(
        "ix_verification_proof_shares_vendor_id",
        "proof_shares",
        ["vendor_id"],
        schema="verification",
    )
    op.create_index(
        "ix_verification_proof_shares_recipient_user_id",
        "proof_shares",
        ["recipient_user_id"],
        schema="verification",
    )


def downgrade() -> None:
    op.drop_index("ix_verification_proof_shares_recipient_user_id", table_name="proof_shares", schema="verification")
    op.drop_index("ix_verification_proof_shares_vendor_id", table_name="proof_shares", schema="verification")
    op.drop_index("ix_verification_proof_shares_proof_job_id", table_name="proof_shares", schema="verification")
    op.drop_index("ix_verification_proof_shares_token", table_name="proof_shares", schema="verification")
    op.drop_table("proof_shares", schema="verification")
