from __future__ import annotations

import json
import os
import re
import uuid
import traceback
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import httpx

from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Artifact, Detection, Email, OpenSafelyJob, Rewrite

from dotenv import load_dotenv

load_dotenv()


# ---- HELPERS ----------------------------------------------------------------

from app.ai_engine import detect_email_with_local_ai

def _ai_enabled() -> bool:
    # Always enabled if we have the service, but we can check if the URL is set
    return bool(os.getenv("OLLAMA_BASE_URL"))


def _heuristic_detect_fallback(e: Email) -> tuple[int, str, list[str]]:
    """
    Robust fallback logic (V7) if AI fails.
    """
    text = (e.body_text or "").lower()
    subject = (e.subject or "").lower()
    urls = e.extracted_urls or []
    
    reasons = []
    score = 0
    
    # 1. Header Analysis
    email_match = re.search(r"<([^>]+)>", e.from_addr or "")
    sender_email = email_match.group(1).lower() if email_match else (e.from_addr or "").lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    sender_reg = _registrable_domain(sender_domain)

    # 2. Keywords
    scam_phrases = ["compensation fund", "winning notification", "inheritance claim", "million usd", "western union"]
    if any(p in text for p in scam_phrases):
        reasons.append("Fallback: Financial scam language detected")
        score += 50 

    urgent_words = ["immediately", "account suspended", "action required", "security alert", "terminate", "verify your account"]
    if any(w in subject or w in text for w in urgent_words):
        reasons.append("Fallback: Urgent/Threatening language")
        score += 25

    # 3. URL Analysis
    generic_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"}
    siblings = {
        "google.com": {"google.dev", "youtube.com", "gmail.com", "googlesource.com", "gstatic.com", "appspot.com", "googleusercontent.com"},
        "microsoft.com": {"office.com", "office365.com", "azure.com", "linkedin.com", "live.com", "sharepoint.com", "microsoftonline.com"},
        "amazon.com": {"media-amazon.com", "amazonaws.com", "aws.amazon.com", "amazon.co.uk", "amazon.ca"},
    }
    
    mismatch_counted = False
    has_ip = False
    
    for u in urls[:20]:
        host = (urlparse(u).hostname or "").strip(".").lower()
        if not host: continue
        host_reg = _registrable_domain(host)

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) and not has_ip:
            reasons.append(f"Fallback: Link uses raw IP address ({host})")
            score += 80
            has_ip = True
        
        if "xn--" in host:
            reasons.append("Fallback: Punycode domain detected")
            score += 80

        if sender_domain and sender_domain not in generic_domains:
            is_safe = False
            if _domain_matches(sender_domain, host): is_safe = True
            if not is_safe and sender_reg in siblings:
                if any(host_reg == _registrable_domain(s) or host.endswith("." + s) for s in siblings[sender_reg]):
                    is_safe = True
            
            if not is_safe and not mismatch_counted:
                 reasons.append(f"Fallback: Link mismatch ({sender_domain} -> {host})")
                 score += 40
                 mismatch_counted = True

    score = min(100, score)
    label = "phishing" if score >= 65 else "suspicious" if score >= 30 else "benign"
    return score, label, reasons


def _strip_links(text: str) -> str:
    return re.sub(r"https?://[^\s'\"]+", "[LINK REMOVED]", text or "", flags=re.IGNORECASE)


def defang_url(u: str) -> str:
    u = u.replace("http://", "hxxp://").replace("https://", "hxxps://")
    u = u.replace(".", "[.]")
    return u


def _registrable_domain(domain: str) -> str:
    if not domain:
        return ""
    d = domain.strip(".").lower()
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    public_suffix_2 = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "gov.uk", "ac.uk"}
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in public_suffix_2 and len(parts) >= 3:
        return last3
    return last2

def _domain_matches(a: str, b: str) -> bool:
    if not a or not b: return False
    a, b = a.strip(".").lower(), b.strip(".").lower()
    ra, rb = _registrable_domain(a), _registrable_domain(b)
    return ra == rb or a.endswith("." + rb) or b.endswith("." + ra)

def extract_urls(text: str) -> list[str]:
    if not text: return []
    rx = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
    return sorted(set(rx.findall(text)))


def html_to_text(html: str) -> str:
    if not html: return ""
    soup = BeautifulSoup(html, "lxml")
    return soup.get_text("\n", strip=True)


def _host_from_url(u: str) -> str | None:
    try:
        return urlparse(u).hostname
    except Exception:
        return None


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))


def _artifact_dir() -> str:
    return os.getenv("ARTIFACT_DIR", os.path.abspath(os.path.join(os.getcwd(), "..", "..", "..", "artifacts")))


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---- API SETUP --------------------------------------------------------------

app = FastAPI(title="PhishNet API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- MODELS -----------------------------------------------------------------

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


# ---- ENDPOINTS --------------------------------------------------------------

@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(sql_text("SELECT 1"))
    return {"ok": True, "artifact_dir": _artifact_dir(), "db": "ok"}

@app.post("/ingest/upload-eml")
async def upload_eml(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await file.read()
    if len(raw) > 5_000_000:
        raise HTTPException(status_code=413, detail="file too large (max 5MB)")

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = msg.get("subject")
    from_addr = msg.get("from")
    to_addr = msg.get("to")
    date_hdr = msg.get("date")
    raw_headers = "".join([f"{k}: {v}\n" for (k, v) in msg.items()])

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
        "body": {"text": e.body_text or ""},
        "links": {"defanged": e.defanged_urls or []},
        "analysis": {
            "detection": (None if not det else {"label": det.label, "risk_score": det.risk_score, "reasons": det.reasons}),
            "rewrite": (None if not rw else {"safe_subject": rw.safe_subject, "safe_body": rw.safe_body, "used_llm": rw.used_llm}),
        },
    }


@app.post("/emails/{email_id}/detect", response_model=DetectionResult)
async def detect(email_id: str, use_llm: bool = True, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")

    subject = e.subject or ""
    from_addr = e.from_addr or ""
    to_addr = e.to_addr or ""
    body_text = e.body_text or ""
    urls: list[str] = e.extracted_urls or []

    # 1. Try Local AI First
    if use_llm and _ai_enabled():
        try:
            print(f"DEBUG: Attempting Local AI detection for {email_id}")
            ai = detect_email_with_local_ai(subject, from_addr, body_text, urls)

            final_score = int(ai.get("score", 0))
            label = str(ai.get("label", "benign")).lower()
            ai_reasons = ai.get("reasons", []) or []
            
            reasons = []
            if isinstance(ai_reasons, list):
                reasons.extend([str(x) for x in ai_reasons if str(x).strip()])
            else:
                reasons.append(str(ai_reasons))

            # Guardrail: Tech Check
            has_ip_link = False
            has_punycode = False
            for u in urls[:25]:
                host = (urlparse(u).hostname or "").strip(".").lower()
                if not host: continue
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host): has_ip_link = True
                if "xn--" in host: has_punycode = True

            if (has_ip_link or has_punycode) and final_score < 80:
                final_score = 85
                label = "phishing"
                reasons.append("System Override: Technical indicator (raw IP / punycode) present.")

            # Final Cleanup
            final_score = max(0, min(100, final_score))
            
            # CONSISTENCY CHECK: Fix Llama 3.2 1B contradictions (e.g. "benign" but score 100)
            if label == "benign" and final_score > 40:
                final_score = 10
            elif label == "phishing" and final_score < 60:
                final_score = 80
                
            seen = set()
            reasons = [x for x in reasons if not (x in seen or seen.add(x))]

            det = Detection(email_id=email_id, label=label, risk_score=final_score, reasons=reasons, created_at=datetime.now(timezone.utc))
            db.add(det)
            db.commit()
            return DetectionResult(label=label, risk_score=final_score, reasons=reasons)

        except Exception as ex:
            print(f"ERROR: Local AI Detection failed (falling back): {ex}")
            traceback.print_exc()  # PRINT FULL ERROR
            # Fall through to heuristics below...

    # 2. Fallback to Robust V7 Heuristics
    print(f"DEBUG: Running Heuristic Fallback for {email_id}")
    score, label, reasons = _heuristic_detect_fallback(e)
    if _ai_enabled():
        reasons.append("Note: AI analysis failed; used heuristics")

    det = Detection(email_id=email_id, label=label, risk_score=score, reasons=reasons, created_at=datetime.now(timezone.utc))
    db.add(det)
    db.commit()

    return DetectionResult(label=label, risk_score=score, reasons=reasons)


@app.post("/emails/{email_id}/rewrite", response_model=RewriteResult)
async def rewrite(email_id: str, use_llm: bool = False, db: Session = Depends(get_db)):
    e = db.query(Email).filter(Email.id == email_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="email not found")
    
    # Rewrite is simple rule-based only in free version
    safe = _strip_links(e.body_text or "")
    used_llm_actual = False

    rw = Rewrite(email_id=email_id, safe_subject=e.subject, safe_body=safe, used_llm=used_llm_actual, created_at=datetime.now(timezone.utc))
    db.add(rw)
    db.commit()

    return RewriteResult(safe_subject=e.subject, safe_body=safe, used_llm=used_llm_actual)


# ... (OpenSafely endpoints below)
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
            sha = None
            db.add(Artifact(job_id=job_id, name=name, rel_path=f"open-safely/{job_id}/{name}", sha256=sha, mime=mime, size_bytes=size, created_at=datetime.now(timezone.utc)))

    db.commit()
    return {
        "job_id": job_id,
        "artifacts": {
            "desktop": f"/open-safely/download/{job_id}?name=desktop.png",
            "mobile": f"/open-safely/download/{job_id}?name=mobile.png",
            "iocs": f"/open-safely/download/{job_id}?name=iocs.json",
            "text": f"/open-safely/download/{job_id}?name=text.txt",
            "meta": f"/open-safely/download/{job_id}?name=meta.json",
        },
    }

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
    a = db.query(Artifact).filter(Artifact.job_id == job_id, Artifact.name == name).first()
    if not a:
        raise HTTPException(status_code=404, detail="not found")

    p = os.path.join(_artifact_dir(), a.rel_path)
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="not found")

    return FileResponse(p, media_type=a.mime or None)