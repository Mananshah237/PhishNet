from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any

from bs4 import BeautifulSoup
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

app = FastAPI(title="PhishNet API", version="0.1.0")


# ---- storage (MVP local) ----------------------------------------------------

def _artifact_dir() -> str:
    return os.getenv("ARTIFACT_DIR", os.path.abspath(os.path.join(os.getcwd(), "..", "..", "..", "artifacts")))


def _emails_dir() -> str:
    p = os.path.join(_artifact_dir(), "emails")
    os.makedirs(p, exist_ok=True)
    return p


def _email_path(email_id: str) -> str:
    return os.path.join(_emails_dir(), f"{email_id}.json")


def _save_email(rec: dict[str, Any]) -> None:
    with open(_email_path(rec["id"]), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)


def _load_email(email_id: str) -> dict[str, Any]:
    p = _email_path(email_id)
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="email not found")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


# ---- utils ------------------------------------------------------------------

def defang_url(u: str) -> str:
    # Keep it simple for MVP: break protocol and dots.
    u = u.replace("http://", "hxxp://").replace("https://", "hxxps://")
    u = u.replace(".", "[.]")
    return u


def extract_urls(text: str) -> list[str]:
    # Conservative URL regex; MVP only.
    if not text:
        return []
    rx = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
    return sorted(set(rx.findall(text)))


def html_to_text(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "lxml")
    return soup.get_text("\n", strip=True)


# ---- API models -------------------------------------------------------------

class EmailListItem(BaseModel):
    id: str
    source: str
    subject: str | None = None
    from_addr: str | None = None
    created_at: str


class DetectionResult(BaseModel):
    label: str
    risk_score: int
    reasons: list[str]


class RewriteResult(BaseModel):
    safe_subject: str | None = None
    safe_body: str
    used_llm: bool


@app.get("/health")
def health():
    return {"ok": True, "artifact_dir": _artifact_dir()}


@app.post("/ingest/upload-eml")
async def upload_eml(file: UploadFile = File(...)):
    raw = await file.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    subject = msg.get("subject")
    from_addr = msg.get("from")

    # Prefer HTML part; fall back to text.
    html_body = ""
    text_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == "attachment":
                continue
            if ctype == "text/html" and not html_body:
                html_body = part.get_content()
            elif ctype == "text/plain" and not text_body:
                text_body = part.get_content()
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            html_body = msg.get_content()
        elif ctype == "text/plain":
            text_body = msg.get_content()

    if not text_body and html_body:
        text_body = html_to_text(html_body)

    combined_for_links = "\n".join([text_body or "", html_body or ""]).strip()
    urls = extract_urls(combined_for_links)

    email_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    rec: dict[str, Any] = {
        "id": email_id,
        "source": "upload:eml",
        "created_at": now,
        "filename": file.filename,
        "headers": {
            "subject": subject,
            "from": from_addr,
        },
        "body": {
            "html": html_body,
            "text": text_body,
        },
        "links": {
            "urls": urls,
            "defanged": [defang_url(u) for u in urls],
        },
        "analysis": {},
    }

    _save_email(rec)
    return {"email_id": email_id}


@app.get("/emails", response_model=list[EmailListItem])
def list_emails():
    items: list[EmailListItem] = []
    for name in sorted(os.listdir(_emails_dir()), reverse=True):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(_emails_dir(), name), "r", encoding="utf-8") as f:
            rec = json.load(f)
        items.append(
            EmailListItem(
                id=rec["id"],
                source=rec.get("source", "unknown"),
                subject=rec.get("headers", {}).get("subject"),
                from_addr=rec.get("headers", {}).get("from"),
                created_at=rec.get("created_at"),
            )
        )
    return items


@app.get("/emails/{email_id}")
def get_email(email_id: str):
    rec = _load_email(email_id)

    # Important: do NOT return raw HTML to the client.
    body = rec.get("body", {})
    return {
        "id": rec["id"],
        "source": rec.get("source"),
        "created_at": rec.get("created_at"),
        "headers": rec.get("headers", {}),
        "body": {
            "text": body.get("text", ""),
        },
        "links": {
            "defanged": rec.get("links", {}).get("defanged", []),
        },
        "analysis": rec.get("analysis", {}),
    }


@app.post("/emails/{email_id}/detect", response_model=DetectionResult)
def detect(email_id: str):
    rec = _load_email(email_id)
    text = (rec.get("body", {}) or {}).get("text", "") or ""

    reasons: list[str] = []
    score = 0

    # MVP heuristics (replace later with model)
    urgent_words = ["urgent", "immediately", "verify", "password", "suspended", "locked", "invoice", "payment"]
    if any(w in text.lower() for w in urgent_words):
        reasons.append("Urgent / coercive language")
        score += 25

    if "http://" in text.lower() or "https://" in text.lower():
        reasons.append("Contains URLs")
        score += 20

    if "gift" in text.lower() or "prize" in text.lower() or "winner" in text.lower():
        reasons.append("Too-good-to-be-true incentive language")
        score += 15

    score = max(0, min(100, score))
    label = "phishing" if score >= 50 else "suspicious" if score >= 25 else "benign"

    rec.setdefault("analysis", {})["detection"] = {"label": label, "risk_score": score, "reasons": reasons}
    _save_email(rec)

    return DetectionResult(label=label, risk_score=score, reasons=reasons)


@app.post("/emails/{email_id}/rewrite", response_model=RewriteResult)
def rewrite(email_id: str, use_llm: bool = False):
    rec = _load_email(email_id)
    subj = (rec.get("headers", {}) or {}).get("subject")
    text = (rec.get("body", {}) or {}).get("text", "") or ""

    # Guaranteed rule-based rewrite: remove manipulation + strip links.
    safe = text
    safe = re.sub(r"https?://[^\s'\"]+", "[LINK REMOVED]", safe, flags=re.IGNORECASE)

    # Tone neutralization (very light MVP)
    safe = re.sub(r"\b(urgent|immediately|act now)\b", "", safe, flags=re.IGNORECASE)
    safe = re.sub(r"\s{2,}", " ", safe).strip()

    used_llm = False
    # LLM rewrite is an optional enhancement; kept as a stub for now.
    if use_llm and os.getenv("OPENAI_API_KEY"):
        # TODO: integrate OpenAI call behind feature flag.
        used_llm = False

    rec.setdefault("analysis", {})["rewrite"] = {"safe_subject": subj, "safe_body": safe, "used_llm": used_llm}
    _save_email(rec)

    return RewriteResult(safe_subject=subj, safe_body=safe, used_llm=used_llm)
