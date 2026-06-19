from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String, default="upload:eml")

    # Tenant/owner scoping: every email belongs to the API caller (owner id
    # resolved from their API key) so callers cannot read or delete each other's
    # data. Defaults to "local" for the auth-disabled local dev mode.
    owner_id: Mapped[str] = mapped_column(String, default="local", index=True)

    subject: Mapped[str | None] = mapped_column(String, nullable=True)
    from_addr: Mapped[str | None] = mapped_column(String, nullable=True)
    to_addr: Mapped[str | None] = mapped_column(String, nullable=True)
    date_hdr: Mapped[str | None] = mapped_column(String, nullable=True)

    # Store raw headers and sanitized bodies for traceability.
    raw_headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_text: Mapped[str] = mapped_column(Text, default="")
    body_html: Mapped[str] = mapped_column(Text, default="")

    extracted_urls: Mapped[list] = mapped_column(JSON, default=list)
    defanged_urls: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    detections: Mapped[list["Detection"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    rewrites: Mapped[list["Rewrite"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    jobs: Mapped[list["OpenSafelyJob"]] = relationship(back_populates="email", cascade="all, delete-orphan")


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email_id: Mapped[str] = mapped_column(String, ForeignKey("emails.id", ondelete="CASCADE"), index=True)

    label: Mapped[str] = mapped_column(String)
    risk_score: Mapped[int] = mapped_column(Integer)
    reasons: Mapped[list] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    email: Mapped[Email] = relationship(back_populates="detections")


class Rewrite(Base):
    __tablename__ = "rewrites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email_id: Mapped[str] = mapped_column(String, ForeignKey("emails.id", ondelete="CASCADE"), index=True)

    safe_subject: Mapped[str | None] = mapped_column(String, nullable=True)
    safe_body: Mapped[str] = mapped_column(Text)
    used_llm: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    email: Mapped[Email] = relationship(back_populates="rewrites")


class OpenSafelyJob(Base):
    __tablename__ = "open_safely_jobs"

    job_id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email_id: Mapped[str] = mapped_column(String, ForeignKey("emails.id", ondelete="CASCADE"), index=True)

    target_url: Mapped[str] = mapped_column(Text)
    allow_target_origin: Mapped[bool] = mapped_column(Boolean, default=False)

    status: Mapped[str] = mapped_column(String, default="queued")  # queued|running|done|failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    email: Mapped[Email] = relationship(back_populates="jobs")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String, ForeignKey("open_safely_jobs.job_id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String)
    rel_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    mime: Mapped[str | None] = mapped_column(String, nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    job: Mapped[OpenSafelyJob] = relationship(back_populates="artifacts")
