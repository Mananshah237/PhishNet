"""API authentication + tenant (owner) resolution.

PhishNet stores highly sensitive email PII, so every data endpoint must require a
caller-supplied API key. Keys are provisioned out-of-band via the
``PHISHNET_API_KEYS`` environment variable and mapped to a stable *owner id* so
that stored emails can be scoped to the caller that created them.

Configuration (env):

* ``PHISHNET_API_KEYS`` — comma-separated ``key`` or ``key:owner_id`` entries.
  Example: ``dev-key-123:web,ext-key-456:extension``. If an entry has no
  ``:owner_id`` the key itself is used as the owner id.
* ``PHISHNET_AUTH_DISABLED`` — set to ``1``/``true`` to disable auth entirely
  (local development / tests only). When disabled, a single shared owner id
  (``"local"``) is used so ownership scoping still behaves deterministically.

The key is read from the ``X-API-Key`` header or an ``Authorization: Bearer``
token.
"""

from __future__ import annotations

import os
import secrets
from typing import Optional

from fastapi import HTTPException, Request, status

_LOCAL_OWNER = "local"


def _auth_disabled() -> bool:
    return os.getenv("PHISHNET_AUTH_DISABLED", "").strip().lower() in {"1", "true", "yes"}


def _load_keys() -> dict[str, str]:
    """Parse ``PHISHNET_API_KEYS`` into a ``{api_key: owner_id}`` mapping."""
    raw = os.getenv("PHISHNET_API_KEYS", "")
    mapping: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            key, owner = entry.split(":", 1)
            key, owner = key.strip(), owner.strip()
        else:
            key, owner = entry, entry
        if key:
            mapping[key] = owner or key
    return mapping


def _extract_key(request: Request) -> Optional[str]:
    key = request.headers.get("x-api-key")
    if key:
        return key.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def require_owner(request: Request) -> str:
    """FastAPI dependency: authenticate the caller and return their owner id.

    Raises 401 when no/invalid credentials are supplied (unless auth is
    explicitly disabled for local development).
    """
    if _auth_disabled():
        return _LOCAL_OWNER

    keys = _load_keys()
    if not keys:
        # Fail closed: if the deployment forgot to configure keys, do not silently
        # run wide-open. Operators must either set PHISHNET_API_KEYS or explicitly
        # opt into PHISHNET_AUTH_DISABLED for local use.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured (set PHISHNET_API_KEYS).",
        )

    presented = _extract_key(request)
    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key (X-API-Key header or Authorization: Bearer).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Constant-time comparison against each configured key.
    for key, owner in keys.items():
        if secrets.compare_digest(presented, key):
            return owner

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key.",
        headers={"WWW-Authenticate": "Bearer"},
    )
