# PhishNet 🛡️🎣

**PhishNet** is a standalone phishing-analysis dashboard designed to safely analyze suspicious emails without exposing the client to danger.

- **Ingest:** Upload `.eml` files (Gmail read-only integration planned).
- **Detect:** Assigns a **risk score (0–100)** with human-readable reasons.
- **Rewrite:** Produces a **safe version** of the email (rule-based default; LLM optional).
- **Open Safely:** Renders suspicious links in an isolated runner, delivering only screenshots to the user.

> **Security Promise (MVP):** The client never receives raw dangerous HTML and never clicks live links.

---

## 🚀 What you get in the MVP

* **Web UI (Next.js):** Responsive email list + dual-panel viewer.
* **API (FastAPI):** Handles ingestion, detection, rewriting, and orchestration.
* **Runner (Playwright):** Isolated sandbox that renders URLs and captures **desktop + mobile screenshots**.
* **Persistence:** Artifacts stored as JSON in `artifacts/` (Postgres container included for future schema migration).

---

## 🏗️ Architecture

```
graph LR
    User[Browser UI] -- HTTP --> API[FastAPI Backend]
    API -- HTTP --> Runner[Playwright Runner]
    API -- Read/Write --> Disk[(Artifacts/JSON)]
    Runner -- Read/Write --> Disk

```

* **apps/web**: Next.js UI
* **apps/api**: FastAPI backend
* **apps/runner**: Playwright sandbox renderer (HTTP service)
* **artifacts/**: Local artifact vault (emails, screenshots, IOCs)

---

## 🔒 Security Policies (MVP)

1. **No raw dangerous HTML** is ever sent to the client.
2. **All links are defanged** and non-clickable in the UI.
3. **Runner is default-deny** for outbound network access.

### "Open Safely" Network Policy

When a user requests to view a suspicious link, two modes are available:

| Mode | Behavior | Use Case |
| --- | --- | --- |
| **Default (Safest)** | **Deny All.** No network traffic allowed. | safest analysis; screenshots may be blank. |
| **Open Safely ✨** | **Target Origin Only.** Allows strictly the destination domain. Blocks ads, trackers, CDNs, and fonts. | Visual verification of the phishing page. |

---

## ⚡ Quickstart (Windows + Docker Desktop)

### Prerequisites

* Docker Desktop (Linux containers mode)
* Git

### 1. Clone the Repository

```powershell
git clone [https://github.com/Mananshah237/PhishNet.git](https://github.com/Mananshah237/PhishNet.git)
cd PhishNet

```

### 2. Run with Docker Compose

*Note: On Windows, `docker` is sometimes not in the PATH for new terminals. Use this exact PowerShell snippet to run the project:*

```powershell
# 1. Set the correct path to the executable
$docker = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"

# 2. Add to PATH for the current session (fixes credential errors)
$env:Path = "C:\Program Files\Docker\Docker\resources\bin;" + $env:Path

# 3. Verify Docker is reachable
& $docker --version

# 4. Build and Run
& $docker compose build
& $docker compose up -d

```

### 3. Open in Browser

* **Web UI:** [http://localhost:3000](https://www.google.com/search?q=http://localhost:3000)
* **API Health:** [http://localhost:8000/health](https://www.google.com/search?q=http://localhost:8000/health)

To stop the services:

```powershell
& $docker compose down

```

---

## ✨ Optional AI (OpenAI)

PhishNet includes an optional LLM-powered rewrite engine.

* **Enabled:** Produces higher-quality, natural-sounding safe summaries.
* **Disabled/Failed:** Automatically falls back to the robust rule-based rewrite.

**How to enable:**

1. Create a `.env` file in the root directory:
```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

```


2. Rebuild the API container:
```powershell
& $docker compose up -d --build api

```


3. In the UI, toggle **"Use LLM rewrite (optional) ✨"** before uploading.

---

## 📖 API Reference (MVP)

**Base URL:** `http://localhost:8000`

### Core Endpoints

* `POST /ingest/upload-eml` - Upload `.eml` file.
* `GET /emails/{email_id}` - Get sanitized email text (no raw HTML).
* `POST /emails/{email_id}/detect` - Run phishing detection logic.
* `POST /emails/{email_id}/rewrite` - Generate safe version (`?use_llm=true` optional).

### Open Safely Endpoints

* `POST /emails/{email_id}/open-safely`
* Body: `{ "link_index": 0, "allow_target_origin": false }`


* `GET /open-safely/{job_id}/desktop.png` - View result.

---

## 🛠️ Troubleshooting

**"Failed to fetch" in UI**

* Ensure the API container is running.
* Check logs: `& $docker compose logs --tail 200 api web`

**Open Safely screenshots are blank**

* This is expected in **Default** mode (network denied). Use **Open Safely ✨** to allow the target page to load.

**Docker command not found**

* Ensure you are using the variable `& $docker` defined in the Quickstart, or add Docker to your system PATH permanently.

---

## 🗺️ Roadmap

* [ ] Gmail OAuth read-only integration
* [ ] Proper DB persistence (Postgres schema + migrations)
* [ ] Background job queue (Redis + RQ/Celery)
* [ ] Advanced IOC extraction
* [ ] Attachment metadata analysis

---

## License

TBD

```

```
