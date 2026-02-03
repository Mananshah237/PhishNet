from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx

from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Artifact, Detection, Email, OpenSafelyJob, Rewrite


def _openai_enabled() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def _openai_model() -> str:
    return os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def _rewrite_prompt(original_text: str) -> str:
    return (
        "You are PhishNet, a security-focused email safety assistant. "
        "Rewrite the email into a SAFE, NEUTRAL version for the user to read.\n\n"
        "Hard rules:\n"
        "- Do NOT include any clickable links. Replace any URL with [LINK REMOVED].\n"
        "- Do NOT include phone numbers, QR codes, or instructions that could lead to compromise.\n"
        "- Remove emotional manipulation, urgency, and threats.\n"
        "- Keep factual details that help the user understand what the email is attempting.\n"
        "- Preserve emojis and friendly formatting if present, but keep tone neutral.\n\n"
        "Return ONLY the rewritten email body (no commentary, no JSON).\n\n"
        f"ORIGINAL EMAIL:\n{original_text}"
    )


def _strip_links(text: str) -> str:
    return re.sub(r"https?://[^\s'\"]+", "[LINK REMOVED]", text or "", flags=re.IGNORECASE)

app = FastAPI(title="PhishNet API", version="0.1.0")

# Allow the local Next.js dev UI to call the API from a different origin (3000 -> 8000).
# MVP policy: open only for local dev origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- storage (artifacts on disk; metadata in Postgres) ----------------------

def _artifact_dir() -> str:
    return os.getenv("ARTIFACT_DIR", os.path.abspath(os.path.join(os.getcwd(), "..", "..", "..", "artifacts")))


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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


def _domain_from_from_header(from_header: str | None) -> str | None:
    if not from_header:
        return None
    m = re.search(r"@([A-Za-z0-9.-]+)", from_header)
    if not m:
        return None
    return m.group(1).lower().strip(".")


def _host_from_url(u: str) -> str | None:
    try:
        return urlparse(u).hostname
    except Exception:
        return None


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


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


class OpenSafelyRequest(BaseModel):
    link_index: int
    allow_target_origin: bool = False


@app.get("/health")
def health(db: Session = Depends(get_db)):
    # Light DB ping
    db.execute(sql_text("SELECT 1"))
    return {"ok": True, "artifact_dir": _artifact_dir(), "db": "ok"}


@app.post("/ingest/upload-eml")
async def upload_eml(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Basic size guard (MVP): 2MB
    raw = await file.read()
    if len(raw) > 2_000_000:
        raise HTTPException(status_code=413, detail="file too large (max 2MB)")

    msg = BytesParser(policy=policy.default).parsebytes(raw)

    subject = msg.get("subject")
    from_addr = msg.get("from")
    to_addr = msg.get("to")
    date_hdr = msg.get("date")

    raw_headers = "".join([f"{k}: {v}\n" for (k, v) in msg.items()])

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
    defanged = [defang_url(u) for u in urls]

    email = Email(
        id=str(uuid.uuid4()),
        source="upload:eml",
        subject=subject,
        from_addr=from_addr,
        to_addr=to_addr,
        date_hdr=date_hdr,
        raw_headers=raw_headers,
        body_text=text_body or "",
        body_html=html_body or "",
        extracted_urls=urls,
        defanged_urls=defanged,
        created_at=datetime.now(timezone.utc),
    )

    db.add(email)
    db.commit()

    return {"email_id": email.id}


@app.get("/emails", response_model=list[EmailListItem])
def list_emails(db: Session = Depends(get_db)):
    emails = db.query(Email).order_by(Email.created_at.desc()).limit(200).all()
    return [
        EmailListItem(
            id=e.id,
            source=e.source,
            subject=e.subject,
            from_addr=e.from_addr,
            created_at=e.created_at.isoformat(),
        )
        for e in emails
    ]


@app.get("/emails/{email_id}")
def get_email(email_id: str, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    det = db.query(Detection).filter(Detection.email_id == email_id).order_by(Detection.id.desc()).first()
    rw = db.query(Rewrite).filter(Rewrite.email_id == email_id).order_by(Rewrite.id.desc()).first()

    # Important: do NOT return raw HTML to the client.
    return {
        "id": e.id,
        "source": e.source,
        "created_at": e.created_at.isoformat(),
        "headers": {
            "subject": e.subject,
            "from": e.from_addr,
            "to": e.to_addr,
            "date": e.date_hdr,
        },
        "body": {
            "text": e.body_text or "",
        },
        "links": {
            "defanged": e.defanged_urls or [],
        },
        "analysis": {
            "detection": (None if not det else {"label": det.label, "risk_score": det.risk_score, "reasons": det.reasons}),
            "rewrite": (None if not rw else {"safe_subject": rw.safe_subject, "safe_body": rw.safe_body, "used_llm": rw.used_llm}),
        },
    }


@app.post("/emails/{email_id}/detect", response_model=DetectionResult)
def detect(email_id: str, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")
    text = e.body_text or ""
    urls: list[str] = e.extracted_urls or []

    reasons: list[str] = []
    score = 0

    t = text.lower()

    # MVP heuristics (replace later with model)
    urgent_words = [
        "urgent",
        "immediately",
        "verify",
        "password",
        "suspended",
        "locked",
        "invoice",
        "payment",
        "action required",
        "security alert",
        "unusual activity",
        "confirm your account",
    ]
    if any(w in t for w in urgent_words):
        reasons.append("Urgent / coercive language")
        score += 25

    cred_words = ["login", "sign in", "verify", "password", "2fa", "otp", "code", "account"]
    if any(w in t for w in cred_words):
        reasons.append("Credential-harvesting language")
        score += 15

    # URL-based signals (more reliable than body text)
    if urls:
        reasons.append(f"Contains {len(urls)} URL(s)")
        score += min(30, 10 + 5 * len(urls))

    sender_domain = _domain_from_from_header(e.from_addr)

    suspicious_tlds = {"zip", "mov", "top", "xyz", "click", "icu"}
    shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly"}

    for u in urls[:10]:
        host = (_host_from_url(u) or "").lower().strip(".")
        if not host:
            continue

        if host.startswith("xn--"):
            reasons.append("Punycode domain (possible homograph)")
            score += 12

        if _looks_like_ip(host):
            reasons.append("Link uses a raw IP address")
            score += 15

        if host in shorteners:
            reasons.append("Uses URL shortener")
            score += 10

        tld = host.split(".")[-1] if "." in host else ""
        if tld in suspicious_tlds:
            reasons.append(f"Suspicious TLD: .{tld}")
            score += 8

        if sender_domain and sender_domain not in host:
            # Weak signal, but good in a demo.
            reasons.append("Sender domain does not match link domain")
            score += 10

        if re.search(r"@", u):
            reasons.append("URL contains '@' (possible obfuscation)")
            score += 10

        if re.search(r"%[0-9A-Fa-f]{2}", u):
            reasons.append("URL contains encoded characters (obfuscation)")
            score += 6

    # Normalize
    reasons = sorted(set(reasons))

    score = max(0, min(100, score))
    label = "phishing" if score >= 60 else "suspicious" if score >= 30 else "benign"

    # Upsert-style: create a new detection row for traceability.
    det = Detection(email_id=email_id, label=label, risk_score=score, reasons=reasons, created_at=datetime.now(timezone.utc))
    db.add(det)
    db.commit()

    return DetectionResult(label=label, risk_score=score, reasons=reasons)


@app.post("/emails/{email_id}/rewrite", response_model=RewriteResult)
async def rewrite(email_id: str, use_llm: bool = False, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")
    subj = e.subject
    text = e.body_text or ""

    # Guaranteed rule-based rewrite: remove manipulation + strip links.
    safe = text
    safe = _strip_links(safe)

    # Tone neutralization (very light MVP)
    safe = re.sub(r"\b(urgent|immediately|act now)\b", "", safe, flags=re.IGNORECASE)
    safe = re.sub(r"\s{2,}", " ", safe).strip()

    used_llm = False

    # Optional AI rewrite (never required; falls back to rule-based safe rewrite).
    if use_llm and _openai_enabled():
        try:
            prompt = _rewrite_prompt(text)
            async with httpx.AsyncClient(timeout=25.0) as client:
                r = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {os.getenv('OPENAI_API_KEY')}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": _openai_model(),
                        "messages": [
                            {"role": "system", "content": "You rewrite emails safely for phishing analysis."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                        "max_tokens": 500,
                    },
                )

            if r.status_code == 200:
                data = r.json()
                candidate = (
                    (((data.get("choices") or [{}])[0]).get("message") or {}).get("content")
                    or ""
                ).strip()
                if candidate:
                    # Enforce link stripping again no matter what.
                    candidate = _strip_links(candidate)
                    safe = candidate
                    used_llm = True
        except Exception:
            # Keep rule-based safe rewrite on failure.
            used_llm = False

    rw = Rewrite(email_id=email_id, safe_subject=subj, safe_body=safe, used_llm=used_llm, created_at=datetime.now(timezone.utc))
    db.add(rw)
    db.commit()

    return RewriteResult(safe_subject=subj, safe_body=safe, used_llm=used_llm)


@app.post("/emails/{email_id}/open-safely")
async def open_safely(email_id: str, req: OpenSafelyRequest, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    urls: list[str] = e.extracted_urls or []
    if req.link_index < 0 or req.link_index >= len(urls):
        raise HTTPException(status_code=400, detail="invalid link_index")

    url = urls[req.link_index]
    job_id = str(uuid.uuid4())

    job = OpenSafelyJob(
        job_id=job_id,
        email_id=email_id,
        target_url=url,
        allow_target_origin=bool(req.allow_target_origin),
        status="queued",
        created_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()

    runner = os.getenv("RUNNER_BASE_URL", "http://runner:7070")

    # Execute synchronously for MVP, but track status like the ADS.
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    db.commit()

    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(
            f"{runner}/render",
            json={
                "url": url,
                "job": job_id,
                "outSubdir": "open-safely",
                "allowTargetOrigin": bool(req.allow_target_origin),
            },
        )

    if r.status_code != 200:
        job.status = "failed"
        job.error = r.text
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=502, detail={"runner_error": r.text, "job_id": job_id})

    job.status = "done"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()

    # Record artifacts (paths are inside the host-mounted artifacts dir)
    job_dir = os.path.join(_artifact_dir(), "open-safely", job_id)
    manifest = {
        "desktop.png": "image/png",
        "mobile.png": "image/png",
        "iocs.json": "application/json",
        "text.txt": "text/plain",
        "meta.json": "application/json",
    }

    for name, mime in manifest.items():
        p = os.path.join(job_dir, name)
        if os.path.exists(p):
            size = os.path.getsize(p)
            # sha256 already in meta.json, but compute here for DB integrity when present.
            sha = None
            try:
                import hashlib

                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                sha = h.hexdigest()
            except Exception:
                sha = None

            db.add(Artifact(job_id=job_id, name=name, rel_path=f"open-safely/{job_id}/{name}", sha256=sha, mime=mime, size_bytes=size, created_at=datetime.now(timezone.utc)))

    db.commit()

    return {"job_id": job_id}


@app.get("/open-safely/status/{job_id}")
def open_safely_status(job_id: str, db: Session = Depends(get_db)):
    job = db.query(OpenSafelyJob).filter(OpenSafelyJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        "job_id": job.job_id,
        "email_id": job.email_id,
        "target_url": job.target_url,
        "allow_target_origin": job.allow_target_origin,
        "status": job.status,
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@app.get("/open-safely/artifacts/{job_id}")
def open_safely_artifacts(job_id: str, db: Session = Depends(get_db)):
    job = db.query(OpenSafelyJob).filter(OpenSafelyJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    artifacts = db.query(Artifact).filter(Artifact.job_id == job_id).order_by(Artifact.id.asc()).all()
    return {
        "job_id": job_id,
        "status": job.status,
        "artifacts": [
            {
                "name": a.name,
                "sha256": a.sha256,
                "mime": a.mime,
                "size_bytes": a.size_bytes,
                "url": f"/open-safely/download/{job_id}?name={a.name}",
            }
            for a in artifacts
        ],
    }


@app.get("/open-safely/download/{job_id}")
def open_safely_download(job_id: str, name: str, db: Session = Depends(get_db)):
    # Prevent path traversal: only allow known artifact names from DB.
    a = db.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == name).first()
    if not a:
        raise HTTPException(status_code=404, detail="not found")

    p = os.path.join(_artifact_dir(), a.rel_path)
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="not found")

    return FileResponse(p, media_type=a.mime or None)
