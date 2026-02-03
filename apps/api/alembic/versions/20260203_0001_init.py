"""init

Revision ID: 20260203_0001
Revises: 
Create Date: 2026-02-03

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "20260203_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "emails",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=True),
        sa.Column("from_addr", sa.String(), nullable=True),
        sa.Column("to_addr", sa.String(), nullable=True),
        sa.Column("date_hdr", sa.String(), nullable=True),
        sa.Column("raw_headers", sa.Text(), nullable=True),
        sa.Column("body_text", sa.Text(), nullable=False),
        sa.Column("body_html", sa.Text(), nullable=False),
        sa.Column("extracted_urls", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("defanged_urls", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "detections",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email_id", sa.String(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detections_email_id", "detections", ["email_id"]) 

    op.create_table(
        "rewrites",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email_id", sa.String(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("safe_subject", sa.String(), nullable=True),
        sa.Column("safe_body", sa.Text(), nullable=False),
        sa.Column("used_llm", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_rewrites_email_id", "rewrites", ["email_id"]) 

    op.create_table(
        "open_safely_jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("email_id", sa.String(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("allow_target_origin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_open_safely_jobs_email_id", "open_safely_jobs", ["email_id"]) 

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(), sa.ForeignKey("open_safely_jobs.job_id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("rel_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=True),
        sa.Column("mime", sa.String(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_artifacts_job_id", "artifacts", ["job_id"]) 


def downgrade() -> None:
    op.drop_index("ix_artifacts_job_id", table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index("ix_open_safely_jobs_email_id", table_name="open_safely_jobs")
    op.drop_table("open_safely_jobs")
    op.drop_index("ix_rewrites_email_id", table_name="rewrites")
    op.drop_table("rewrites")
    op.drop_index("ix_detections_email_id", table_name="detections")
    op.drop_table("detections")
    op.drop_table("emails")
