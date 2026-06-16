# PhishNet Browser Extension (Chrome / Edge)

A free, Manifest V3 extension that scans the email you are reading in Gmail for
phishing, using your PhishNet backend. It adds a **Scan email** button to Gmail,
shows a risk verdict with reasons, and **learns from your feedback on-device** so
verdicts adapt to you over time.

## How it works

```
Gmail page ──(scrape subject/from/body/links)──► extension
        │
        ▼
   POST {backendUrl}/analyze   ──►  PhishNet backend (BERT + heuristics [+ LLM])
        │                                   │
        ▼                                   ▼
   on-device personalization layer  ◄── risk_score / label / reasons
   (per-user, chrome.storage, free)
        │
        ▼
   verdict panel + Mark safe / Mark phishing  ──► updates the on-device model
```

- **Email access:** reads the open message from the Gmail DOM. No OAuth, no Google
  API quota, nothing to verify — so it is free to ship and use. The robust upgrade
  is the Gmail API via `chrome.identity` OAuth (`gmail.readonly`,
  `messages.get?format=raw`), which needs Google verification + a CASA security
  assessment; that is a later step, not required for this build.
- **Personalization** (`personalization.js`) is 100% local: it learns trusted
  senders and a per-user calibration bias from your "Mark safe / Mark phishing"
  feedback, stored in `chrome.storage.local`. Nothing leaves your device.

## Install (unpacked, for development / personal use)

1. Start the PhishNet backend (default `http://localhost:8002`).
2. Go to `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode**.
4. Click **Load unpacked** and select this `apps/extension` folder.
5. Open Gmail, open an email, click **🛡 Scan email**.

Set a different backend URL (e.g. a hosted instance) in the extension's
**Settings** (options page).

## Backend requirement

The backend must allow the extension origin. The backend already permits
`chrome-extension://*` via CORS, and you can set extra allowed origins with the
`PHISHNET_ALLOWED_ORIGINS` environment variable. The extension calls
`POST /analyze` with `{subject, from_addr, body_text, body_html, urls, method}`.

## Publishing (later)

- **Chrome Web Store:** one-time $5 developer fee → users get an "Add to Chrome"
  button. **Edge Add-ons** and **Firefox** are free.
- A public build needs a hosted backend (users do not run one locally) and a
  privacy policy. Keep the LLM engine off the free tier to keep hosting cheap;
  BERT + heuristics + DNS auth run fine on CPU.
