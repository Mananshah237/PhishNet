"""API-layer tests: authentication, CORS, tenant ownership, and PII deletion.

These complement tests/test_detection.py (heuristic unit tests). They spin up the
FastAPI app against a throwaway SQLite database and exercise the security
controls added in the 2026-06-18 hardening pass.

Run: cd apps/api && python -m pytest ../../tests/test_api.py -v
"""

import os
import sys
import tempfile

import pytest

# --- Configure environment BEFORE importing the app -------------------------
# Each engine/detector that needs the network is left disabled; we only need the
# heuristic path, which is deterministic and offline.
_TMP_DB = os.path.join(tempfile.gettempdir(), "phishnet_test_api.db")
if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["PHISHNET_API_KEYS"] = "key-alice:alice,key-bob:bob"
os.environ.pop("PHISHNET_AUTH_DISABLED", None)
os.environ.pop("OLLAMA_BASE_URL", None)  # keep LLM disabled

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from fastapi.testclient import TestClient  # noqa: E402

from app.db import engine  # noqa: E402
from app.models import Base  # noqa: E402
from app import main  # noqa: E402

# Create the schema (incl. owner_id) on the throwaway DB.
Base.metadata.create_all(bind=engine)

client = TestClient(main.app)

ALICE = {"X-API-Key": "key-alice"}
BOB = {"X-API-Key": "key-bob"}

_SAMPLE = {
    "subject": "Lunch tomorrow?",
    "from_addr": "coworker@example.com",
    "body_text": "Want to grab lunch tomorrow around noon?",
    "method": "heuristic",
}


def _analyze_as(headers):
    return client.post("/analyze", json=_SAMPLE, headers=headers)


# --- Authentication ----------------------------------------------------------

def test_analyze_requires_api_key():
    r = client.post("/analyze", json=_SAMPLE)
    assert r.status_code == 401


def test_analyze_rejects_bad_key():
    r = client.post("/analyze", json=_SAMPLE, headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_analyze_accepts_valid_key():
    r = _analyze_as(ALICE)
    assert r.status_code == 200
    body = r.json()
    assert set(["label", "risk_score", "reasons"]).issubset(body.keys())


def test_bearer_token_also_works():
    r = client.post("/analyze", json=_SAMPLE, headers={"Authorization": "Bearer key-alice"})
    assert r.status_code == 200


def test_list_requires_auth():
    assert client.get("/emails").status_code == 401


def test_delete_requires_auth():
    assert client.delete("/emails/some-id").status_code == 401


def test_health_is_public():
    assert client.get("/health").status_code == 200


# --- Tenant isolation / ownership -------------------------------------------

def test_owner_isolation_on_list_and_read():
    # Alice creates an email; Bob must not see or read it.
    r = _analyze_as(ALICE)
    assert r.status_code == 200

    alice_list = client.get("/emails", headers=ALICE).json()
    assert len(alice_list) >= 1
    eid = alice_list[0]["id"]

    bob_list = client.get("/emails", headers=BOB).json()
    assert all(item["id"] != eid for item in bob_list)

    # Bob cannot read Alice's email (404, not 200).
    assert client.get(f"/emails/{eid}", headers=BOB).status_code == 404
    # Alice can.
    assert client.get(f"/emails/{eid}", headers=ALICE).status_code == 200


def test_owner_cannot_delete_others_email():
    r = _analyze_as(ALICE)
    eid = client.get("/emails", headers=ALICE).json()[0]["id"]

    # Bob's delete must not affect Alice's row.
    assert client.delete(f"/emails/{eid}", headers=BOB).status_code == 404
    assert client.get(f"/emails/{eid}", headers=ALICE).status_code == 200

    # Alice can delete her own.
    assert client.delete(f"/emails/{eid}", headers=ALICE).status_code == 200
    assert client.get(f"/emails/{eid}", headers=ALICE).status_code == 404


def test_delete_all_scoped_to_owner():
    _analyze_as(ALICE)
    _analyze_as(BOB)
    before_bob = len(client.get("/emails", headers=BOB).json())
    assert before_bob >= 1

    # Alice purges all of HER data; Bob's is untouched.
    r = client.delete("/emails", headers=ALICE)
    assert r.status_code == 200
    assert len(client.get("/emails", headers=ALICE).json()) == 0
    assert len(client.get("/emails", headers=BOB).json()) == before_bob


# --- CORS --------------------------------------------------------------------

def test_cors_does_not_reflect_wildcard_methods():
    # Preflight from an allowed extension origin: response must reflect the
    # restricted method/header set, never "*".
    r = client.options(
        "/analyze",
        headers={
            "Origin": "chrome-extension://abcdefghij",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )
    allow_methods = r.headers.get("access-control-allow-methods", "")
    assert "*" not in allow_methods
    assert "POST" in allow_methods


def test_cors_blocks_unlisted_origin():
    r = client.get(
        "/emails",
        headers={"Origin": "https://evil.example.com", "X-API-Key": "key-alice"},
    )
    # Origin not reflected for a disallowed origin.
    assert r.headers.get("access-control-allow-origin") != "https://evil.example.com"
