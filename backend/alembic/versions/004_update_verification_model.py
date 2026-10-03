"""update verification model for proofs

Revision ID: 004
Revises: 003
Create Date: 2026-10-01 21:28:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('verification_requests', sa.Column('proof_job_id', sa.Uuid(), nullable=True), schema='verification')
    op.execute("UPDATE verification.verification_requests SET proof_job_id = gen_random_uuid()")
    op.alter_column('verification_requests', 'proof_job_id', nullable=False, schema='verification')
    op.drop_column('verification_requests', 'proof_artifact', schema='verification')

def downgrade():
    op.add_column('verification_requests', sa.Column('proof_artifact', sa.Text(), nullable=True), schema='verification')
    op.execute("UPDATE verification.verification_requests SET proof_artifact = 'downgraded'")
    op.alter_column('verification_requests', 'proof_artifact', nullable=False, schema='verification')
    op.drop_column('verification_requests', 'proof_job_id', schema='verification')
