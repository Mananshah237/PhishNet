
# PhishNet: AI-Powered Email Security Sandbox

**PhishNet** is a secure, localized environment for analyzing suspicious emails. It combines three independent detection methods — a **fine-tuned DistilBERT classifier**, **Llama 3.2** (via Ollama), and a **multi-signal heuristic engine** — with optional **mail authentication context** (SPF / DKIM / DMARC from received headers), a sandboxed **Open Safely** preview, and **safe rewrite** tooling.

## Key Features

* **Three detection methods:** Run **Heuristic**, **LLM** (Llama 3.2), **BERT**, or **All** together. With “All”, scores are combined (max score, most severe label, merged reasons), then optionally adjusted when strong authentication headers are present (see below).
* **Fine-tuned DistilBERT:** `distilbert-base-uncased` trained on multiple public email/spam datasets with structured inputs (`subject`, `from`, `body`, `urls`), **max sequence length 512**, and metadata-driven inference so training and serving stay aligned. The bundled model reports **~99.3%** test accuracy and **~99.3%** F1 on its holdout split (see `apps/api/bert/model/training_meta.json`). Weights ship in-repo via **Git LFS** (`model.safetensors`).
* **BERT technical overrides:** Raw IP links, punycode (IDN), and deep subdomain patterns can **raise** the BERT-derived score when the model under-reacts to hard technical signals.
* **LLM analysis:** Llama 3.2 1B runs locally through Ollama using a **structured prompt** (0–100 scoring bands, 8-point phishing checklist, legitimate-mail indicators) and **JSON-only** replies, with defensive parsing if the model wraps output in markdown.
* **Multi-signal heuristic engine:** Sender, content, URL, cross-correlation, and negative-signal layers (brand spoofing, punycode, suspicious TLDs, credential language, URL–sender mismatch, third-party / ESP allowlisting, etc.) — works without GPU or Ollama.
* **Mail authentication (headers):** Parses **`Authentication-Results`** (and related patterns) for **SPF**, **DKIM**, and **DMARC** outcomes as reported by the receiving provider. Values are **not re-verified against DNS** by PhishNet; they are shown for analyst context and used in scoring when all three are **pass**.
* **Combined-score adjustment:** If headers indicate **SPF + DKIM + DMARC** all **pass**, the **final combined** risk score is reduced (to reduce false positives on legitimate ESP/marketing mail). A reason line is appended to the detection output when this applies.
* **Dashboard:** Upload `.eml`, pick detection mode, view score/verdict/reasons, **SPF/DKIM/DMARC chips** on the email detail view, **safe rewrite** (strip links; optional LLM polish), and **Open Safely** (sandboxed render).
* **API:** FastAPI backend — ingest, list/delete emails, run detection, rewrite, Open Safely jobs and artifacts (see **API overview** below).
* **Privacy:** Self-hosted via Docker; inference runs locally (no paid cloud APIs). Ollama pulls the chat model on first boot; training scripts may download Hugging Face datasets when you retrain.

## Detection Methodology

### BERT classifier

* **Model:** `distilbert-base-uncased` binary classifier, weights under `apps/api/bert/model/`.
* **Input format:** Structured text aligned with training — subject, sender, body (truncated), and up to 10 URLs, joined with `[SEP]` (see `bert_engine.py` and `training_meta.json` → `input_format`).
* **Training:** `apps/api/bert/train.py` can load **multiple Hugging Face datasets** (spam/phishing/labeled email sources), apply **class-weighted** loss, **warmup**, and train for **6 epochs** at **512** tokens when on GPU (fp16 on CUDA). Local CSV/JSON under `bert/dataset/` is still supported.
* **Train / validation / test split (shipped checkpoint):** After class balancing, `training_meta.json` records **54,804** total labeled rows (`total_samples`). **46,583** rows are used for training (`train_samples`). The script then holds out **15%** (**8,221** rows), splits that block **50/50** with stratification into **validation** and **test** — about **4,110** and **4,111** rows respectively (exact counts differ by one because the holdout is odd). Training uses the **train** split; per-epoch evaluation uses **validation**; the numbers in `training_meta.json` (**accuracy**, **F1**, **precision**, **recall**) come from the **test** split only.

### Heuristic engine

Runs independent checks across layers:

* **Sender:** Display-name brand spoofing (50+ brands), suspicious TLDs, domain entropy, registrable-domain alignment with links, ESP/third-party domain allowlisting.
* **Content:** Scam phrases, credential harvesting, financial bait, attachments/urgency (conservatively weighted).
* **URL:** Raw IPs, punycode/IDN, suspicious TLDs, free hosting / dynamic DNS, subdomain abuse, brand-in-subdomain vs sender domain, credential-style paths, `data:`/`javascript:` URIs, shorteners in impersonation context.
* **Cross-correlation:** Compounding signals (e.g. brand + deceptive URL), classic phishing pattern bonuses, multi-indicator multipliers.
* **Negative signals:** Unsubscribe hints, URLs aligned with sender, generic webmail senders, short plain-text with no links.

Heuristics are always available; BERT requires model files; LLM requires Ollama.

### LLM (Ollama / Llama 3.2)

Uses OpenAI-compatible **`OLLAMA_BASE_URL`** (e.g. `http://ollama:11434/v1`). The prompt asks for a single JSON object: `score`, `label` (`benign` | `suspicious` | `phishing`), and `reasons[]`. **Technical guardrails** in the API can bump the score when raw IP or punycode links are present but the LLM under-scores.

### Mail authentication (SPF / DKIM / DMARC)

* **Source:** `app/auth_results.py` scans stored **raw headers** for `Authentication-Results` (RFC-style `spf=`, `dkim=`, `dmarc=` tokens and common variants).
* **UI/API:** Email detail JSON includes `mail_authentication` (`source`, `spf`, `dkim`, `dmarc`, explanatory `note`). The web UI shows **pass / fail / softfail / neutral** styling; missing auth is expected for synthetic or stripped messages.
* **Scoring:** Only affects the **post-combination** score when a full **pass/pass/pass** pattern is seen; PhishNet does **not** perform live SPF/DKIM/DMARC DNS checks.

---

## Architecture

```
User / Browser
    |
    v
Next.js Frontend (port 3000)
    |
    v
FastAPI Backend (port 8000)
    |--- DistilBERT (in-process, PyTorch + Transformers)
    |--- Ollama / Llama 3.2 1B (port 11434)
    |--- Heuristic engine (pure Python)
    |--- Mail auth parser (header text only)
    |--- SQLite (local file under apps/api/data/)
    |--- Headless Chromium Runner (port 7070)
            |
            v
        Local artifact storage (./artifacts)
```

---

## Prerequisites

* **Docker Desktop** (running and updated)
* **Git LFS** — BERT weights (`model.safetensors`) use LFS. Run `git lfs install` before cloning.
* No API keys for core operation; Ollama pulls Llama 3.2 1B on first stack start.

---

## Quick Start

### 1. Install Git LFS

```bash
git lfs install
```

### 2. Clone

```bash
git clone https://github.com/Rabib001/PhishNet2.git
cd PhishNet2
```

Pull LFS objects if needed:

```bash
git lfs pull
```

### 3. Configure environment

Create a `.env` in the **repository root** (values match `docker-compose`):

```ini
DATABASE_URL=sqlite:///data/phishnet.db
OLLAMA_BASE_URL=http://ollama:11434
```

### 4. Launch

```bash
docker compose up -d --build
```

First run: image builds, dependencies install, Ollama may download **Llama 3.2 1B** (~1.3GB).

### 5. Access

* **Frontend:** http://localhost:3000  
* **API docs:** http://localhost:8000/docs  

### 6. Verify detection backends

```bash
curl http://localhost:8000/detect/methods
```

Example:

```json
{"heuristic": true, "llm": true, "bert": true}
```

* `bert: false` → check LFS / `bert/model/`  
* `llm: false` → wait for Ollama or check `docker compose logs ollama`

### SQLite database file

The app uses **`apps/api/data/phishnet.db`** (bind-mounted in Docker). The database file is **local and environment-specific** and is **not intended to be committed** to Git (see `.gitignore`). After clone, the API creates or uses the file under `apps/api/data/` when you run migrations or ingest email.

### Running without Docker (local dev)

```bash
cd apps/api
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Set `DATABASE_URL` if you want a path outside the default. For LLM detection, run Ollama on the host and point `OLLAMA_BASE_URL` at it (e.g. `http://127.0.0.1:11434`).

### Retraining BERT (optional)

```bash
cd apps/api
pip install -r bert/requirements-train.txt
python bert/train.py
```

Training pulls Hugging Face datasets as configured in `train.py`, uses GPU when available, and overwrites `bert/model/` (including `training_meta.json`). Duration depends on hardware and dataset sizes.

---

## API overview

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness + DB check |
| POST | `/ingest/upload-eml` | Upload `.eml` (max 5MB), returns `email_id` |
| GET | `/emails` | List recent emails |
| GET | `/emails/{email_id}` | Full detail: headers, body, links, `mail_authentication`, cached analysis/rewrite |
| DELETE | `/emails/{email_id}` | Remove email |
| GET | `/detect/methods` | `{ heuristic, llm, bert }` availability |
| POST | `/emails/{email_id}/detect` | Run detection; returns `label`, `risk_score`, `reasons` |
| POST | `/emails/{email_id}/rewrite` | Safe rewrite (`use_llm` optional) |
| POST | `/emails/{email_id}/open-safely` | Start sandbox render job |
| GET | `/open-safely/status/{job_id}` | Job status |
| GET | `/open-safely/artifacts/{job_id}` | Artifact metadata |
| GET | `/open-safely/download/{job_id}` | Download artifact file |

---

## Usage (dashboard)

1. **Upload** a `.eml` file.  
2. **Select method:** Heuristic, LLM, BERT, or All.  
3. **Analyze** — view 0–100 score, label (benign / suspicious / phishing), and reason strings (per method + any mail-auth adjustment note).  
4. **Mail authentication** — inspect SPF/DKIM/DMARC as reported in headers (informational; not DNS-validated).  
5. **Rewrite** — generate a safer plain-text view; optionally use the LLM.  
6. **Open Safely** — render in the isolated runner; review screenshots and extracted IOCs without loading the email in your main browser.

---

## Sample analysis output

```
Email: "Your PayPal account has been limited"
From: PayPal Security <security@paypa1-verify.xyz>

Risk Score: 100/100 — PHISHING

Indicators:
  - Display name impersonates 'paypal' but sender domain is paypa1-verify.xyz
  - Sender domain uses suspicious TLD: paypa1-verify.xyz
  - Credential harvesting language: 'enter your password'
  - Urgency/pressure language detected
  - Link uses raw IP address: 185.234.72.11
  - Credential-harvesting URL path on domain unrelated to sender
  - Brand impersonation + deceptive URL infrastructure
  - 8 independent indicators detected
```

(If the same message arrived with SPF/DKIM/DMARC **pass** in `Authentication-Results`, the **combined** pipeline may lower the final score and add an explicit reason line.)

---

## Security architecture (Open Safely)

* Email HTML can load **tracking pixels, scripts, and external resources** — risky on an analyst workstation.  
* **Direct clicks** leak IP and browser fingerprint.  
* PhishNet’s **runner** uses headless Chromium in a **separate container** with a restrictive network policy: only the target origin can be allowed; other requests are blocked.  
* Output is **screenshots + extracted text + IOCs**, not an interactive browser session on the host.  
* Runner jobs are **ephemeral** per render.

---

## Troubleshooting

### "AI analysis unavailable; using heuristics"

* Ollama still pulling the model or unhealthy — check `docker compose logs ollama` and `docker compose exec ollama ollama list`.

### Frontend cannot reach API

* Confirm API is up: `docker compose logs -f api`  
* `NEXT_PUBLIC_API_BASE` should point at the API from the **browser** (e.g. `http://localhost:8000`).

### BERT unavailable after clone

* Run `git lfs pull` and ensure `apps/api/bert/model/model.safetensors` exists.

---

## Project structure

* **`apps/api`** — FastAPI app (`main.py`), DB models, heuristics, `ai_engine.py`, `bert_engine.py`, **`auth_results.py`** (SPF/DKIM/DMARC parsing)  
* **`apps/api/bert/`** — Model weights, `train.py`, training requirements  
* **`apps/api/data/`** — Local SQLite directory (`phishnet.db` created at runtime; not tracked in Git)  
* **`apps/web`** — Next.js dashboard (upload, detection, mail-auth UI, Open Safely integration)  
* **`apps/runner`** — Headless Chromium Open Safely service  
* **`artifacts/`** — Screenshots and job artifacts  

---

## License

MIT License. Use responsibly for educational and defensive security purposes.
