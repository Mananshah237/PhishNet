# PhishNet — Status

_Last updated: 2026-06-18_

## 2026-06-18 — Security hardening pass

Worked through `SECURITY_AUDIT.md`. Done:

- **API auth + tenant isolation:** every endpoint now requires an API key/bearer
  token (`app/security.py`, `PHISHNET_API_KEYS`); emails carry an `owner_id` and all
  reads/lists/deletes are owner-scoped (migration `..._email_owner`). A caller can no
  longer read or delete everyone's stored mail.
- **`/analyze` 422 bug fixed:** removed `from __future__ import annotations` from
  `app/main.py` — under PEP 563 the slowapi `@limiter.limit` wrapper left the body
  model as an unresolved string, so FastAPI misread the body as a query param and
  **every analyze request 422'd**. Eager annotations restore correct routing.
- **CORS** restricted to the methods/headers actually used (no more `*`).
- **Email PII:** removed the raw-LLM-response debug logging; LLM prompt now wraps the
  email in a delimited "treat as untrusted data" block (prompt-injection mitigation);
  added owner-scoped retention/deletion endpoints.
- **Rate limiting** on `/analyze` and the Chromium-spawning `/open-safely`.
- **Extension XSS:** `content.js` builds the verdict panel via DOM/`textContent`
  instead of interpolating backend values into `innerHTML`.
- **Runner SSRF** (`server.js`): blocks IPv6 loopback/ULA, link-local + cloud
  metadata `169.254.169.254`, and resolves-then-validates against DNS rebinding.
- **Supply chain:** lockfiles for `apps/web` + `apps/runner`; pinned torch/transformers.
- **Tests + CI:** `tests/test_api.py` (auth, ownership, CORS) added — full suite
  **58 passing**; added `.github/workflows/ci.yml`; `docs/DATA_RETENTION.md`.

(The recency-weighted training work below is unchanged.)

## 2026-06-18 — Recency-weighted training + use-all-data scaling

`bert/train.py` now scales up and weights examples by how recent their source is.

- **Recency weighting** ("range by time/age"): each row weighted by source vintage
  with exponential decay (half-life `PHISHNET_RECENCY_HALFLIFE_YEARS`, default 4y).
  Enron(2002)≈0.02, SMS(2011)≈0.07, github(2020)≈0.35, zefang(2022)≈0.50,
  Deysi(2023)≈0.60, cybersectony(2024)≈0.71. Applied as a per-sample weight in the
  loss (WeightedTrainer, CE reduction="none"; `remove_unused_columns=False`).
- **Use-all-data**: `PHISHNET_BALANCE` = `cap` (default; keep all minority +
  majority up to `PHISHNET_MAX_IMBALANCE`× , default 2) / `downsample` (old) / `all`.
  Stops discarding the ~5k benign that hard-balancing threw away.
- **Age cutoff**: `PHISHNET_MAX_AGE_YEARS` (0=off) drops sources older than N years.
- **Speed knobs for big runs**: `PHISHNET_MAX_LENGTH` (default 512; 256 ~2× faster),
  `PHISHNET_EPOCHS` (use ~3 for large data). Per-source vintages in `SOURCE_VINTAGE`.
- Strategy recorded in `training_meta.json` (balance_mode, recency, halflife, age).

Honest ceiling: ~27k labeled *phishing* exist across current sources, so a clean
balanced 1M isn't available publicly — to actually approach that, add more corpora
to `load_all_hf_datasets` (tag each with a `SOURCE_VINTAGE`). Recency weighting is
the real precision lever, not raw count.

Recommended big run (PowerShell):
  $env:PHISHNET_BALANCE="all"; $env:PHISHNET_EPOCHS="3"; $env:PHISHNET_MAX_LENGTH="256"; python train.py

---

## 2026-06-15 — Free browser extension + BERT skew fix

Goal: turn PhishNet into a **free Gmail extension** backed by the same engines,
with detection that **personalizes to each user on-device**. Local-first, host-ready.

Done this pass:
- **Fixed BERT train/serve format skew** (`app/bert_engine.py`): inference fed a
  4-field `[SEP]` string but the model was trained on 2 fields
  (`subject [SEP] body`). Now matches training exactly (folds sender+links into
  body, honors `training_meta.json["input_format"]`). Main cause of weak standalone
  BERT accuracy.
- **`POST /analyze` JSON endpoint** (`app/main.py`) for the extension (no .eml
  needed); reuses the existing detect + mail-auth pipeline.
- **Configurable CORS** via `PHISHNET_ALLOWED_ORIGINS`; `chrome-extension://` /
  `moz-extension://` allowed by regex.
- **Trainer trains longer safely** (`bert/train.py`): default epochs 12
  (`PHISHNET_EPOCHS`) + `EarlyStoppingCallback` on val F1 (`PHISHNET_EARLY_STOP_PATIENCE`).
- **New extension** `apps/extension/` (Manifest V3): Gmail DOM scrape (no OAuth),
  verdict panel + feedback, **on-device personalization** (`personalization.js`,
  learns trusted senders + per-user calibration bias in `chrome.storage.local`),
  options + popup.
- Tests: `tests/test_detection.py` **46 passed** after changes.

Next: retrain BERT with the aligned format on GPU; calibrated weighted ensemble
combiner; real SPF/DKIM/DMARC DNS verification; host backend (LLM off the free
tier) + Chrome Web Store publish; Outlook add-in; extension PNG icons.

Honest constraints: in-browser full DistilBERT retraining isn't feasible —
personalization is a lightweight on-device layer over the fixed base model.
Public Gmail API needs OAuth verification + CASA ($500–4k/yr); DOM-scrape MVP
avoids it. LLM hosting needs a GPU.

---

## State: working & verified, synced to origin/main

- Local checkout was **6 commits behind** `origin/main` with 17 divergent uncommitted
  changes (including a deleted BERT model pointer). Resolved by stashing all local work
  (recoverable: `git stash list` → `stash@{0}`) and fast-forwarding to `origin/main`.
- `git lfs pull` materialized the real **268 MB** `model.safetensors` (it was previously a
  missing/pointer file — the root cause of "detection returns nothing").

## Verified

BERT classifier loaded from the shipped checkpoint:

| Input | Result |
|-------|--------|
| Spoofed-PayPal phishing mail, `.tk` credential URL | `score=99, label=phishing` |
| Plain coworker "lunch tomorrow?" mail | `score=0, label=benign` |

Model holdout metrics: **acc 99.3% / F1 99.3%**.

## Run

```bash
git lfs pull            # REQUIRED — else bert: false
docker compose up -d --build
# Frontend http://localhost:3002 · API http://localhost:8002/docs (Ollama 11434)
```

Ports are offset (web 3002 / API 8002) so PhishNet runs alongside VEXIS (3000/8000) and AegisScan (3001/8001).

## Next (see README → Optimization roadmap)

GPU inference path · concurrent detectors (`asyncio.gather`) · startup warmup · int8
quantization · optional DNS-verified SPF/DKIM/DMARC · pin Ollama model digest.
