"""
Extract SPF / DKIM / DMARC outcomes from message headers.

These values usually come from the recipient's MTA (e.g. Microsoft, Google) and
are **not** re-verified by PhishNet against DNS. For raw .eml exports they are
still very useful; for synthetic or stripped messages they may be missing.
"""

from __future__ import annotations

import re
from typing import Any

# Common result tokens (RFC 8601 + provider quirks)
_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)=([a-z]+)",
    re.IGNORECASE,
)


def _unfold_header_blocks(raw: str) -> list[tuple[str, str]]:
    """Split raw header string into (lowercase_name, unfolded_value) pairs."""
    if not raw or not raw.strip():
        return []
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[tuple[str, str]] = []
    current_name: str | None = None
    current_parts: list[str] = []

    for line in lines:
        if not line.strip():
            break
        if line[0] in " \t":
            if current_name is not None:
                current_parts.append(line.strip())
            continue
        if current_name is not None:
            out.append((current_name, " ".join(current_parts)))
        if ":" not in line:
            current_name = None
            current_parts = []
            continue
        name, _, rest = line.partition(":")
        current_name = name.strip().lower()
        current_parts = [rest.strip()]

    if current_name is not None:
        out.append((current_name, " ".join(current_parts)))
    return out


def _aggregate_results(value: str) -> dict[str, str]:
    """
    From one Authentication-Results value, collect best-known spf/dkim/dmarc.
    If multiple dkim= lines exist, fail beats neutral beats pass for security display.
    """
    found: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
    for m in _RESULT_RE.finditer(value):
        kind = m.group(1).lower()
        res = m.group(2).lower()
        if kind in found:
            found[kind].append(res)

    priority = {"fail": 3, "permerror": 3, "temperror": 2, "softfail": 2, "neutral": 1, "none": 1, "ignore": 1, "pass": 0, "bestguesspass": 0}

    def pick(values: list[str]) -> str | None:
        if not values:
            return None
        values = list(dict.fromkeys(values))  # preserve order, unique
        best = None
        best_p = -1
        for v in values:
            p = priority.get(v, 1)
            if p > best_p:
                best_p = p
                best = v
        return best

    return {
        "spf": pick(found["spf"]) or "",
        "dkim": pick(found["dkim"]) or "",
        "dmarc": pick(found["dmarc"]) or "",
    }


def parse_authentication_from_raw_headers(raw_headers: str | None) -> dict[str, Any]:
    """
    Parse Authentication-Results and (fallback) ARC-Authentication-Results.

    Returns a dict suitable for JSON: verdicts may be null if absent.
    """
    if not raw_headers:
        return _empty_payload()

    blocks = _unfold_header_blocks(raw_headers)

    ar_values = [v for n, v in blocks if n == "authentication-results"]
    arc_values = [v for n, v in blocks if n == "arc-authentication-results"]

    source = "none"
    chosen = ""
    if ar_values:
        # Last Authentication-Results is often the mailbox provider's summary
        chosen = ar_values[-1]
        source = "authentication-results"
    elif arc_values:
        chosen = arc_values[-1]
        source = "arc-authentication-results"

    if not chosen:
        return _empty_payload()

    agg = _aggregate_results(chosen)
    return {
        "source": source,
        "spf": agg["spf"] or None,
        "dkim": agg["dkim"] or None,
        "dmarc": agg["dmarc"] or None,
        "note": (
            "Values are parsed from the uploaded message headers (typically added by "
            "the recipient's mail provider). PhishNet does not re-run SPF/DKIM/DMARC "
            "against DNS on this server."
        ),
    }


def _empty_payload() -> dict[str, Any]:
    return {
        "source": "none",
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "note": (
            "No Authentication-Results (or ARC) header found. The .eml may be "
            "from a client export without provider auth stamps, or headers were stripped."
        ),
    }
