"""enforce_proof_size

Revision ID: 007
Revises: 006
Create Date: 2026-10-02 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006_add_proof_archive_hash'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Alter Column proof_artifact from TEXT to VARCHAR(5000)
    # We must explicitly cast or alter the column.
    
    # ProofJob
    op.alter_column('proof_jobs', 'proof_artifact',
               existing_type=sa.Text(),
               type_=sa.String(length=5000),
               existing_nullable=True,
               schema='zkp')
               
    # SegmentProof
    op.alter_column('segment_proofs', 'proof_artifact',
               existing_type=sa.Text(),
               type_=sa.String(length=5000),
               existing_nullable=True,
               schema='zkp')


def downgrade() -> None:
    op.alter_column('segment_proofs', 'proof_artifact',
               existing_type=sa.String(length=5000),
               type_=sa.Text(),
               existing_nullable=True,
               schema='zkp')

    op.alter_column('proof_jobs', 'proof_artifact',
               existing_type=sa.String(length=5000),
               type_=sa.Text(),
               existing_nullable=True,
               schema='zkp')
