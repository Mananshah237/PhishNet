# PhishNet — Status

_Last updated: 2026-06-10_

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
