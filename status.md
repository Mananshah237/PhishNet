# PhishNet — Status

_Last updated: 2026-06-15_

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
