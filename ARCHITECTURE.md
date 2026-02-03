# PhishNet — Architecture Notes (Draft)

## Components
- **Web UI**: Next.js (React) + Tailwind
- **API**: FastAPI (Python)
- **Runner**: Playwright (Chromium) in an isolated container/job runner
- **DB**: Postgres
- **Artifacts**: local filesystem (MVP), later S3/MinIO

## Key Safety Invariants
- Client never receives raw dangerous HTML.
- All URLs displayed are defanged and non-clickable.
- Open Safely returns only read-only artifacts (images + sanitized text + IOCs).
- Runner is ephemeral; artifacts are checksummed + provenance UUID tracked.
- Sandbox has outbound network blocked by default.

## Proposed API Surface (MVP)
### Email ingestion
- `POST /ingest/upload-eml` → {email_id}
- `GET /emails` → list
- `GET /emails/{id}` → details (sanitized for UI)

### Gmail (read-only)
- `GET /gmail/oauth/start`
- `GET /gmail/oauth/callback`
- `GET /gmail/messages` → list
- `GET /gmail/messages/{gmail_id}/ingest` → {email_id}

### Detection + rewrite
- `POST /emails/{id}/detect` → {risk_score, label, reasons[]}
- `POST /emails/{id}/rewrite` → {safe_version}

### Open Safely
- `POST /open-safely` body: {email_id, url}
  → {job_id}
- `GET /open-safely/{job_id}/status`
- `GET /open-safely/{job_id}/artifacts`

## Artifact Layout (local, MVP)
`artifacts/{job_uuid}/`
- `desktop.png`
- `mobile.png`
- `text.txt`
- `iocs.json`
- `meta.json`

## IOC Extraction (MVP)
- Domains from final URL + any observed navigations
- Defanged domain list
- IPs found in text/URL
- Optional: certificate info / headers (later)

## Notes on Network Blocking
Layering recommended:
1. Container/network policy: runner container has no outbound network.
2. Playwright request interception: route all requests and abort (belt-and-suspenders).

(Exact implementation depends on the runtime environment.)
