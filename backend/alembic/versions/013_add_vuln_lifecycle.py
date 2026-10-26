"""add vulnerability snapshot lifecycle columns

Revision ID: 013
Revises: 012
Create Date: 2026-10-09

"""

from alembic import op
import sqlalchemy as sa

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("vulnerability_snapshots", sa.Column("authoritative_smt_root", sa.String(length=128), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("frozen_by", sa.Uuid(), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("approved_by", sa.Uuid(), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("revoked_by", sa.Uuid(), nullable=True), schema="vulnerability")
    op.add_column("vulnerability_snapshots", sa.Column("revocation_reason", sa.String(length=512), nullable=True), schema="vulnerability")

    op.create_foreign_key("fk_vuln_snapshots_frozen_by", "vulnerability_snapshots", "users", ["frozen_by"], ["id"], source_schema="vulnerability", referent_schema="public", ondelete="SET NULL")
    op.create_foreign_key("fk_vuln_snapshots_approved_by", "vulnerability_snapshots", "users", ["approved_by"], ["id"], source_schema="vulnerability", referent_schema="public", ondelete="SET NULL")
    op.create_foreign_key("fk_vuln_snapshots_revoked_by", "vulnerability_snapshots", "users", ["revoked_by"], ["id"], source_schema="vulnerability", referent_schema="public", ondelete="SET NULL")

def downgrade() -> None:
    op.drop_constraint("fk_vuln_snapshots_revoked_by", "vulnerability_snapshots", schema="vulnerability", type_="foreignkey")
    op.drop_constraint("fk_vuln_snapshots_approved_by", "vulnerability_snapshots", schema="vulnerability", type_="foreignkey")
    op.drop_constraint("fk_vuln_snapshots_frozen_by", "vulnerability_snapshots", schema="vulnerability", type_="foreignkey")
    
    op.drop_column("vulnerability_snapshots", "revocation_reason", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "revoked_by", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "revoked_at", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "approved_by", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "approved_at", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "frozen_by", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "frozen_at", schema="vulnerability")
    op.drop_column("vulnerability_snapshots", "authoritative_smt_root", schema="vulnerability")
