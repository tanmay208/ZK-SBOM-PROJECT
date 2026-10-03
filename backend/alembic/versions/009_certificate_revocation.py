"""certificate_revocation

Revision ID: 009
Revises: 008
Create Date: 2026-10-03 12:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add revocation columns to verification_certificates
    op.add_column(
        'verification_certificates',
        sa.Column('is_revoked', sa.Boolean(), nullable=False, server_default=sa.false()),
        schema='verification',
    )
    op.add_column('verification_certificates', sa.Column('revoked_at', sa.DateTime(), nullable=True), schema='verification')
    op.add_column('verification_certificates', sa.Column('revoked_reason', sa.String(length=255), nullable=True), schema='verification')
    op.create_check_constraint(
        'chk_certificate_revocation_state',
        'verification_certificates',
        '(is_revoked = FALSE AND revoked_at IS NULL) OR '
        '(is_revoked = TRUE AND revoked_at IS NOT NULL)',
        schema='verification',
    )


def downgrade() -> None:
    op.drop_constraint(
        'chk_certificate_revocation_state',
        'verification_certificates',
        schema='verification',
        type_='check',
    )
    op.drop_column('verification_certificates', 'revoked_reason', schema='verification')
    op.drop_column('verification_certificates', 'revoked_at', schema='verification')
    op.drop_column('verification_certificates', 'is_revoked', schema='verification')
