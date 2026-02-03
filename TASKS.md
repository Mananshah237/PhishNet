# PhishNet — Sprint 4 Implementation Plan (Draft)

> Goal: MVP that ingests emails (Gmail read-only or .eml upload), detects phishing + risk score, produces safe rewrite, and supports **Open Safely** screenshot-based preview (desktop/mobile) + IOC list — with strict safety controls.

## Assumptions (confirm)
- Local/dev deploy via Docker Compose.
- Frontend: Next.js + Tailwind.
- Backend: FastAPI.
- Sandbox runner: Playwright Chromium in an isolated container with **no outbound network**.
- Artifact store: local filesystem for MVP.

## Phase 0 — Repo + Foundations (0.5–1 day)
- [ ] Create monorepo layout: `apps/web`, `apps/api`, `apps/runner`, `infra/`
- [ ] Add Dockerfiles for api/web/runner
- [ ] Add `docker-compose.yml` for Postgres + api + web (+ runner as job image)
- [ ] Add env templates (`.env.example`) + secrets guidance
- [ ] Basic CI lint/test hooks (optional MVP)

## Phase 1 — Data Model + Storage (0.5–1.5 days)
- [ ] Postgres schema (or SQLAlchemy models + Alembic migrations):
  - emails (source, gmail ids, headers, bodies)
  - detections (risk score, labels, features)
  - rewrites (safe text)
  - screenshot_jobs (status, timestamps, provenance uuid)
  - artifacts (paths, sha256, mime)
- [ ] Local artifact directory conventions
- [ ] Provenance + sha256 calculation utilities

## Phase 2 — Email Ingestion (1–3 days)
- [ ] Gmail OAuth (read-only): connect, token storage, refresh
- [ ] Fetch message list (light metadata)
- [ ] Fetch single message + parse:
  - html/text body
  - from/sender
  - links (URL extraction)
- [ ] Upload `.eml` endpoint + parser
- [ ] Normalize/defang URLs for display

## Phase 3 — Detection + Rewrite (1–3 days)
- [ ] `/detect` endpoint:
  - baseline heuristic features + optional model placeholder
  - risk score 0–100
  - reasons list (urgent tone, spoofing hints, risky domain patterns)
- [ ] `/rewrite` endpoint:
  - rule-based neutralization + link placeholdering
  - optional LLM integration behind a feature flag
- [ ] Store outputs and tie to email id

## Phase 4 — Open Safely Pipeline (2–5 days)
### Runner (Playwright)
- [ ] Runner accepts job payload: target URL + job uuid
- [ ] **Network egress blocked** (confirm mechanism: Playwright routing + container network isolation)
- [ ] Render and capture:
  - desktop screenshot
  - mobile screenshot (emulation)
  - extracted visible text
  - IOC extraction (domains, ips, redirects if observable)
- [ ] Produce `meta.json` (timestamps, versions, sha256)

### Orchestrator (FastAPI)
- [ ] `/screenshot` create job
- [ ] `/status/{job_id}` polling
- [ ] `/artifacts/{job_id}` returns signed/served images + iocs + text (sanitized)
- [ ] Ensure: **no raw HTML** returned to client

## Phase 5 — Web UI (2–5 days)
- [ ] Login stub (or simple local auth for MVP)
- [ ] Email list view (Gmail / uploads)
- [ ] Email detail:
  - left panel: original w/ highlights + defanged links
  - right panel: safe rewrite
- [ ] Open Safely modal:
  - job progress
  - desktop/mobile images
  - IOC list

## Phase 6 — Demo + Docs (1–2 days)
- [ ] Sample phishing `.eml` set + benign control
- [ ] Demo script
- [ ] Minimal README runbook

## Open Questions (need answers)
1. What’s the target **deadline/demo date**?
2. Are we using an LLM for rewrite now (OpenAI/local), or rules-only for MVP?
3. Where will OAuth client secrets live (local env vs vault)?
4. What authentication do we need for the dashboard (none/local vs real auth)?
5. Strictness of sandbox: do we allow DNS but block HTTP, or block all egress at container level?
