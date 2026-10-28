"""verification_idempotency_result_width

Revision ID: 008
Revises: 007
Create Date: 2026-10-03 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Increase column width for 'result' to 50
    op.alter_column('verification_requests', 'result',
               existing_type=sa.String(length=20),
               type_=sa.String(length=50),
               existing_nullable=True,
               schema='verification')
               
    # 2. Add UniqueConstraint for verification request idempotency
    op.create_unique_constraint(
        'uq_verification_request_idempotency',
        'verification_requests',
        ['user_id', 'sbom_root', 'vulnerability_db_root', 'policy_hash', 'proof_job_id'],
        schema='verification'
    )


def downgrade() -> None:
    # Remove unique constraint
    op.drop_constraint('uq_verification_request_idempotency', 'verification_requests', schema='verification', type_='unique')
    
    # Decrease column width for 'result' back to 20
    op.alter_column('verification_requests', 'result',
               existing_type=sa.String(length=50),
               type_=sa.String(length=20),
               existing_nullable=True,
               schema='verification')
