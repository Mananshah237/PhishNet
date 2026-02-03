# PhishNet — Project Brief (Handoff)

## One-line
PhishNet is a standalone web dashboard that connects to a user’s Gmail (read-only) or accepts uploaded emails, detects phishing, rewrites the email safely (neutralized version), and provides a secure **“Open Safely”** preview by rendering suspicious content in an isolated sandbox and returning **non-interactive screenshots + indicators**.

## Problem
Most phishing tooling either blocks messages completely or adds a simple warning banner, but users still open emails out of curiosity and click links “just to see,” risking compromise. Security teams also lose context if content is stripped/blocked.

**Goal:** let users understand attacker intent and content **without exposing their device**.

## Differentiators / Core Features
### 1) Dual Panel Viewer (core UI)
When an email is analyzed:
- **Left:** Original email, risky sections highlighted; links defanged and non-clickable.
- **Right:** AI-rewritten safe version (neutral tone, no manipulation, no dangerous links).

### 2) “Open Safely” (security feature; MVP = screenshot-only)
For suspicious links:
- Server-side runner opens the link in an **isolated sandbox**
- Captures **desktop + mobile screenshots** and extracts **IOCs**
- Dashboard shows only **non-interactive screenshots** + sanitized text/indicators

**MVP constraint:** no interactive VM/browser for the user.

## What PhishNet is NOT
- Not a full email client: no sending, threading, folders, SMTP/IMAP replacement.
- It’s an **analysis + safe preview** platform integrating with email providers.

## End-to-End User Flow
1. User logs into PhishNet web dashboard.
2. User chooses one:
   - Connect Gmail (OAuth read-only)
   - Upload suspicious email (.eml)
   - (Optional fallback) paste raw headers/body
3. Ingest + extract:
   - HTML body, text body
   - sender/from info
   - headers (optional)
   - URLs
   - attachment metadata (MVP)
4. Run phishing detection:
   - phishing vs benign
   - risk score (0–100)
   - suspicious patterns (urgency, spoofing, risky URLs)
5. Run safe rewrite:
   - neutralize tone
   - remove emotional manipulation
   - remove/replace links with placeholders
6. Display results (dual panel view).
7. If links are suspicious, user clicks **Open Safely**:
   - server runs sandbox rendering
   - returns screenshots + IOC list + sanitized snippet

## Architecture (High Level)
### Frontend
- Next.js / React + Tailwind
- Email list (Gmail / uploaded)
- Dual panel viewer
- Screenshot preview modal
- IOC components
- Status polling + job progress

### Backend API
- Python FastAPI
- Endpoints for:
  - Gmail OAuth / token handling
  - email ingestion (upload/fetch)
  - `/detect` (phishing inference)
  - `/rewrite` (safe rewrite)
  - `/screenshot` + `/status` (sandbox pipeline)
  - artifacts retrieval

### Sandbox / “Open Safely” Worker
- Docker container / isolated runner
- Playwright (headless Chromium)
- Produces artifacts:
  - `desktop.png`
  - `mobile.png`
  - `text.txt`
  - `iocs.json`
  - `meta.json` (hashes, provenance UUID)

### Storage
- Postgres: emails, rewrites, risk scores, job metadata, artifact references
- Artifact store: local folder for MVP; MinIO/S3 later
- Encryption at rest required in final

## Non-negotiable Security Policies
- No raw dangerous HTML delivered to client
- All links displayed are **defanged / non-clickable**
- Sandbox blocks outbound HTTP/HTTPS by default (no network egress)
- Runner is ephemeral (destroy after artifacts collected)
- Artifacts are read-only (images + sanitized text only)
- Track provenance (job UUID, SHA256 checksums; audit logs later)

## Why Playwright (vs EyeWitness)
- EyeWitness is CLI/report oriented, not an API microservice
- Not designed for multi-user safe preview systems
- Lacks strong sandbox controls + artifact vault design

So we use a custom Playwright runner with explicit network blocking and artifact outputs.

## Current Status
- Sprint 3: SRS v1.0 complete; sandbox approach researched; architecture + threat model defined; MVP steps planned
- Sprint 4 (planned):
  1) Build Playwright runner container (Phase 1)
  2) Build FastAPI orchestration endpoints (Phase 2)
  3) UI modal for screenshots + IOCs (Phase 3)

## Concrete Deliverables
A) Email ingestion
- Gmail OAuth read-only connect
- Fetch message list
- Parse selected email (HTML/text/links)
- Upload .eml flow

B) Phishing detection
- Baseline model + metrics
- Risk score output
- Service endpoint

C) Rewrite engine
- Rule-based defang + LLM rewrite
- Store rewritten result

D) Open Safely pipeline
- Playwright runner outputs artifacts
- Orchestrator: `/screenshot`, `/status`, `/artifacts`
- UI modal to display screenshots + IOCs

E) UI
- Dashboard + viewer
- Dual panels + risk highlights
- Screenshot preview + IOC viewer

F) Docs + demo
- SRS / ADS / final report
- sprint review slides
- demo scenario w/ sample phishing email

## Demo Scenario
- Connect Gmail or upload a phishing `.eml`
- High risk score
- Dual panel: original highlighted + safe rewrite
- Open Safely: screenshots (desktop/mobile) + IOC list
- Show prevention of direct exposure

## MVP Scope Boundaries
- Attachments: metadata only (no detonation)
- Open Safely: screenshot-only
- Gmail integration: read-only
- Not an inbox replacement
