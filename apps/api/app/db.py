from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        # Fallback for local testing without docker
        url = "sqlite:///./phishnet.db"
    return url


# SQLite specific: check_same_thread=False is required for FastAPI
engine = create_engine(
    database_url(), 
    connect_args={"check_same_thread": False},
    pool_pre_ping=True
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
