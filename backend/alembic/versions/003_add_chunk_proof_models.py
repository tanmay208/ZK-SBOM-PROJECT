"""add chunk proof models

Revision ID: 003
Revises: 002
Create Date: 2026-10-01 21:26:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade():
    # Create chunk_proof_sets table
    op.create_table(
        'chunk_proof_sets',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('proof_job_id', sa.Uuid(), nullable=False),
        sa.Column('chunk_index', sa.Integer(), nullable=False),
        sa.Column('total_chunks', sa.Integer(), nullable=False),
        sa.Column('component_start', sa.Integer(), nullable=False),
        sa.Column('component_count', sa.Integer(), nullable=False),
        sa.Column('components_commit', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        schema='zkp'
    )

    # Create segment_proofs table
    op.create_table(
        'segment_proofs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('chunk_id', sa.Uuid(), nullable=False),
        sa.Column('chunk_index', sa.Integer(), nullable=False),
        sa.Column('total_chunks', sa.Integer(), nullable=False),
        sa.Column('segment_index', sa.Integer(), nullable=False),
        sa.Column('proof_artifact', sa.Text(), nullable=True),
        sa.Column('proof_artifact_hash', sa.String(length=128), nullable=True),
        sa.Column('components_commit', sa.String(length=128), nullable=True),
        sa.Column('hash_in_commit', sa.String(length=128), nullable=True),
        sa.Column('hash_out_commit', sa.String(length=128), nullable=True),
        sa.Column('global_sbom_root', sa.String(length=128), nullable=True),
        sa.Column('vulnerability_db_root', sa.String(length=128), nullable=True),
        sa.Column('policy_hash', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        schema='zkp'
    )


def downgrade():
    op.drop_table('segment_proofs', schema='zkp')
    op.drop_table('chunk_proof_sets', schema='zkp')
