"""add proof_archive_hash

Revision ID: 006_add_proof_archive_hash
Revises: 005_add_topology_constraints
Create Date: 2026-10-02 11:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '006_add_proof_archive_hash'
down_revision = '005_add_topology_constraints'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('proof_jobs', sa.Column('proof_archive_hash', sa.String(128), nullable=True), schema='zkp')

def downgrade():
    op.drop_column('proof_jobs', 'proof_archive_hash', schema='zkp')
