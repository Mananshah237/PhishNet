from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def database_url() -> str:
    # docker-compose supplies DATABASE_URL
    url = os.getenv("DATABASE_URL")
    if not url:
        # Safe local default (mainly for non-docker dev)
        url = "postgresql+psycopg://phishnet:phishnet@localhost:5432/phishnet"
    return url


engine = create_engine(database_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
