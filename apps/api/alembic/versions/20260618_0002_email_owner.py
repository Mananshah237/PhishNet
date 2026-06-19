"""add owner_id to emails for tenant isolation

Revision ID: 20260618_0002
Revises: 20260203_0001
Create Date: 2026-06-18

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260618_0002"
down_revision: Union[str, None] = "20260203_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emails",
        sa.Column("owner_id", sa.String(), nullable=False, server_default="local"),
    )
    op.create_index("ix_emails_owner_id", "emails", ["owner_id"])


def downgrade() -> None:
    op.drop_index("ix_emails_owner_id", table_name="emails")
    op.drop_column("emails", "owner_id")
