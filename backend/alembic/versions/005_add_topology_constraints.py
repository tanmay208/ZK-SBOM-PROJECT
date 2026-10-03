"""add topology constraints

Revision ID: 005_add_topology_constraints
Revises: 004_update_verification_model
Create Date: 2026-10-02 10:41:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '005_add_topology_constraints'
down_revision = '004'
branch_labels = None
depends_on = None

def upgrade():
    # Chunk constraints
    op.create_unique_constraint('uq_chunk_index_per_job', 'chunk_proof_sets', ['proof_job_id', 'chunk_index'], schema='zkp')
    op.create_check_constraint('chk_chunk_index_bounds', 'chunk_proof_sets', 'chunk_index >= 0 AND chunk_index < 32', schema='zkp')
    
    # Segment constraints
    op.create_unique_constraint('uq_segment_index_per_chunk', 'segment_proofs', ['chunk_id', 'segment_index'], schema='zkp')
    op.create_check_constraint('chk_segment_index_bounds', 'segment_proofs', 'segment_index >= 0 AND segment_index < 8', schema='zkp')
    
    # Certificate constraint (1:1 with verification request)
    op.create_unique_constraint('uq_cert_per_request', 'verification_certificates', ['verification_request_id'], schema='verification')

def downgrade():
    op.drop_constraint('uq_cert_per_request', 'verification_certificates', schema='verification', type_='unique')
    
    op.drop_constraint('chk_segment_index_bounds', 'segment_proofs', schema='zkp', type_='check')
    op.drop_constraint('uq_segment_index_per_chunk', 'segment_proofs', schema='zkp', type_='unique')
    
    op.drop_constraint('chk_chunk_index_bounds', 'chunk_proof_sets', schema='zkp', type_='check')
    op.drop_constraint('uq_chunk_index_per_job', 'chunk_proof_sets', schema='zkp', type_='unique')
