# PhishNet 🛡️🎣

PhishNet is a standalone phishing-analysis dashboard that:

- Ingests suspicious emails (**upload `.eml`** for MVP; Gmail read-only integration is planned)
- Detects phishing and assigns a **risk score (0–100)** with human-readable reasons
- Produces a **safe rewrite** of the email (rule-based always; LLM optional)
- Provides **Open Safely**: a screenshot-only preview of suspicious links rendered in an isolated runner

> **Security promise (MVP):** The client never receives raw dangerous HTML and never clicks live links.

---

## What you get in the MVP

- Web UI (Next.js): email list + dual-panel viewer
- API (FastAPI): ingestion, detection, rewrite, Open Safely orchestration
- Runner (Playwright): renders suspicious URLs in a sandbox and outputs **desktop + mobile screenshots** + IOCs
- Postgres container included (schema usage is planned; MVP stores email records as JSON in `artifacts/`)

---

## Architecture (high level)

```
Browser (UI)  ──HTTP──▶  FastAPI (API)  ──HTTP──▶  Runner (Playwright)
      │                    │                           │
      │                    └── reads/writes artifacts ──┘
      └──── shows ONLY sanitized data + screenshots ─────
```

- **apps/web**: Next.js UI
- **apps/api**: FastAPI backend
- **apps/runner**: Playwright sandbox renderer (HTTP service)
- **artifacts/**: local artifact vault for MVP (emails, screenshots, IOC JSON)

---

## Non‑negotiable security policies (MVP)

- **No raw dangerous HTML delivered to the client**
- **All displayed links are defanged / non-clickable**
- **Open Safely is screenshot-only** (no interactive remote browsing in MVP)
- Runner is **default-deny** for outbound network access

### Open Safely network policy (MVP)

Two modes:

1) **Default (safest):** deny all outbound network
   - Runner loads nothing external
   - Screenshot may be blank/error page (still valuable for demo + grading)

2) **Optional (explicit):** `allow_target_origin=true`
   - Allow only the **exact target origin**
   - Block everything else: third-party scripts, CDNs, analytics, ads, fonts, trackers
   - Block obvious private/localhost targets

Policy statement:
> “Allow only the target origin; deny everything else.”

---

## Quickstart (Windows + Docker Desktop)

### Prereqs
- Docker Desktop (Linux containers)
- Git

### Clone
```powershell
git clone https://github.com/Mananshah237/PhishNet.git
cd PhishNet
```

### Run locally
Docker Desktop installs `docker.exe`, but on some systems `docker-credential-desktop.exe` is not on PATH in a fresh terminal.
Use this exact command set:

```powershell
# From repo root
$docker = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"

# Ensure Docker credential helper is discoverable for this terminal session
[Environment]::SetEnvironmentVariable(
  "Path",
  "C:\Program Files\Docker\Docker\resources\bin;" + [Environment]::GetEnvironmentVariable("Path","Process"),
  "Process"
)

& $docker compose build
& $docker compose up -d
& $docker ps
```

### Open in browser
- Web UI: http://localhost:3000
- API health: http://localhost:8000/health

### Stop
```powershell
& $docker compose down
```

---

## How to use (demo flow)

1) Open http://localhost:3000
2) Upload a suspicious `.eml` file
3) The UI will automatically:
   - run **Detection** (risk score + reasons)
   - generate **Safe rewrite** (rule-based always)
4) In **Defanged links**, click:
   - **Open Safely 👀 (no network)** or
   - **Open Safely ✨ (allow target origin)**

A modal appears with:
- Desktop screenshot
- Mobile screenshot

Artifacts are stored under:
- `artifacts/emails/<email_id>.json`
- `artifacts/open-safely/<job_id>/desktop.png`
- `artifacts/open-safely/<job_id>/mobile.png`
- `artifacts/open-safely/<job_id>/iocs.json`
- `artifacts/open-safely/<job_id>/meta.json`

---

## API (MVP)

Base: `http://localhost:8000`

### Health
- `GET /health`

### Email ingestion
- `POST /ingest/upload-eml` (multipart form-data: `file`)

### Email browsing
- `GET /emails`
- `GET /emails/{email_id}` (returns **text only**, no raw HTML)

### Detection + rewrite
- `POST /emails/{email_id}/detect`
- `POST /emails/{email_id}/rewrite?use_llm=false|true`

### Open Safely
- `POST /emails/{email_id}/open-safely`
  - body: `{ "link_index": 0, "allow_target_origin": false }`
- `GET /open-safely/{job_id}/desktop.png`
- `GET /open-safely/{job_id}/mobile.png`
- `GET /open-safely/{job_id}/iocs.json`
- `GET /open-safely/{job_id}/meta.json`

---

## Troubleshooting

### UI shows "Failed to fetch"
- Ensure API is running and CORS is enabled (it is in this repo).
- Check container status:

```powershell
& $docker compose ps
& $docker compose logs --tail 200 api web
```

### Open Safely screenshots look blank
That’s expected in **default-deny** mode (no network). Use **allow target origin** mode to load only the destination origin.

### Docker command not found
Use the full path:
- `C:\Program Files\Docker\Docker\resources\bin\docker.exe`

---

## Hosting (notes)

This project includes a Playwright/Chromium runner, which is heavy and often not compatible with “free” hosting.

Recommended for demos:
- **Run locally using Docker Compose** (most reliable)

If you want public hosting:
- Host **web** on Vercel/Cloudflare Pages
- Host **api + runner** on a container/VPS (cheap VPS is simplest)

---

## Roadmap (post-MVP)

- Gmail OAuth read-only integration
- Proper DB persistence (Postgres schema + migrations)
- Background job queue (Redis + RQ/Celery)
- More robust IOC extraction
- Attachment metadata → detonation (future)
- Audit logs + encryption at rest (final hardening)

---

## License

TBD (add one if/when needed).
