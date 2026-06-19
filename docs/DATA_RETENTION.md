# Data Retention & Deletion — PhishNet

PhishNet analyzes **email content**, which is highly sensitive personal data
(message bodies, headers, sender/recipient addresses, embedded URLs). This
document records how that data is minimized, stored, retained, and deleted.

## What we store

| Data | Location | Sensitivity |
|------|----------|-------------|
| Subject, from/to, raw headers | `emails` table (SQLite by default) | PII |
| Body text + HTML | `emails` table | High — full message content |
| Extracted / defanged URLs | `emails` table | Medium |
| Detection results (label, score, reasons) | response + `emails` | Low |
| Owner id (tenant) | `emails.owner_id` | Scoping key |

Every row carries an `owner_id`; reads, lists, and deletes are scoped to the
authenticated caller (see `require_owner` in `apps/api/app/main.py`). One tenant
cannot read or delete another's email.

## Data minimization

- The LLM detector receives the email **as data inside a delimited block** with an
  instruction to treat it as untrusted (prompt-injection mitigation), and only when
  the LLM method is requested.
- Raw LLM responses and email bodies are **not** written to application logs (the
  former `DEBUG: AI Raw Response` print was removed in the 2026-06-18 hardening).
- The browser extension's on-device personalization stores trusted senders and a
  calibration bias in `chrome.storage.local` — it never ships raw mail to a server
  beyond the `/analyze` request the user initiates.

## Retention

| Data | Default retention | Mechanism |
|------|-------------------|-----------|
| Analyzed emails | 30 days | `POST /admin/retention/purge` deletes rows older than the cutoff for the caller. |
| Open-safely sandbox artifacts | 7 days | Pruned with the job. |

Retention is owner-scoped; a purge only affects the caller's own data.

## Deletion (data-subject requests)

- `DELETE /emails/{id}` — delete a single email (owner-scoped, 404 for non-owners).
- `DELETE /emails` — purge **all** of the caller's stored emails.
- `POST /admin/retention/purge` — delete the caller's emails older than the cutoff.

These satisfy a user's right-to-erasure for the data PhishNet holds.

## Compliance posture (honest)

- **GDPR**: email content is processed only to produce a phishing verdict for the
  requesting user; deletion endpoints above support erasure. Self-hosting keeps the
  data on the operator's own infrastructure.
- **HIPAA**: out of scope. PhishNet is not a HIPAA-eligible service; do not route
  PHI-bearing mail through a hosted instance without a separate assessment and BAA.

## TODO

- Encrypt body/HTML columns at rest (currently cleartext in SQLite) for hosted
  deployments.
- Schedule the retention purge (currently an on-demand endpoint).
