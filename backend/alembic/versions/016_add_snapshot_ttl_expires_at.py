"""add snapshot ttl expires_at column

Revision ID: 016
Revises: 015
Create Date: 2026-10-22

Schema Updates:
vulnerability.vulnerability_snapshots:
  - Add nullable expires_at column: TIMESTAMP WITH TIME ZONE NULL
  - Add index ix_vuln_snapshots_expires_at on (expires_at)
  - Historical snapshots retain expires_at = NULL (grandfathered)
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "016"
down_revision: Union[str, None] = "015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerability_snapshots",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        schema="vulnerability",
    )
    op.create_index(
        "ix_vuln_snapshots_expires_at",
        "vulnerability_snapshots",
        ["expires_at"],
        schema="vulnerability",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_vuln_snapshots_expires_at",
        table_name="vulnerability_snapshots",
        schema="vulnerability",
    )
    op.drop_column(
        "vulnerability_snapshots",
        "expires_at",
        schema="vulnerability",
    )
