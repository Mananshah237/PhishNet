// On-device personalization layer — the part that "adapts to each person".
//
// The shared DistilBERT/heuristic model stays fixed on the backend. This layer
// learns from THIS user's corrections and the senders they trust, entirely in
// the browser (chrome.storage.local). Nothing leaves the device, it costs
// nothing to run, and every user ends up with a verdict tuned to their own mail.
//
// What it learns:
//   1. Per-sender trust  — senders the user repeatedly marks safe/phishing.
//   2. A global calibration bias — corrects systematic over/under-scoring for
//      this user via simple online gradient updates on their feedback.

const PN_STORE_KEY = "pn_personalization";
const PN_LR = 0.12;          // learning rate for the bias term
const PN_BIAS_CLAMP = 40;    // max absolute calibration shift (points)

async function pnLoadState() {
  const out = await chrome.storage.local.get(PN_STORE_KEY);
  return out[PN_STORE_KEY] || { senders: {}, bias: 0, count: 0 };
}

async function pnSaveState(state) {
  await chrome.storage.local.set({ [PN_STORE_KEY]: state });
}

function pnSenderKeys(fromAddr) {
  const m = String(fromAddr || "").match(/[\w.+-]+@([\w.-]+)/);
  const email = m ? m[0].toLowerCase() : "";
  const domain = m ? m[1].toLowerCase() : "";
  return { email, domain };
}

function pnLabelFor(score) {
  if (score >= 65) return "phishing";
  if (score >= 35) return "suspicious";
  return "benign";
}

// Adjust a raw backend result using what we know about this user.
async function pnAdapt(result, meta) {
  const state = await pnLoadState();
  const { email, domain } = pnSenderKeys(meta.from);
  let score = result.risk_score;
  const notes = [];

  const rec = state.senders[email] || state.senders[domain];
  if (rec) {
    const net = (rec.safe || 0) - (rec.phish || 0);
    if (net >= 2) {
      score -= Math.min(35, net * 8);
      notes.push(`Personalized: you trust this sender (marked safe ${rec.safe}×)`);
    } else if (net <= -1) {
      score += Math.min(40, Math.abs(net) * 15);
      notes.push(`Personalized: you flagged this sender before (${rec.phish}×)`);
    }
  }

  if (Math.abs(state.bias) >= 3) {
    score += state.bias;
    notes.push(
      `Personalized: calibrated ${state.bias > 0 ? "+" : ""}${Math.round(state.bias)} from your ${state.count} corrections`
    );
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return {
    risk_score: score,
    label: pnLabelFor(score),
    reasons: [...result.reasons, ...notes],
    personalized: notes.length > 0,
  };
}

// Record a user correction and update the on-device model.
async function pnRecordFeedback(meta, modelScore, userLabel) {
  const state = await pnLoadState();
  const { email, domain } = pnSenderKeys(meta.from);
  const isPhish = userLabel === "phishing";

  for (const key of [email, domain].filter(Boolean)) {
    const rec = state.senders[key] || { safe: 0, phish: 0 };
    if (isPhish) rec.phish += 1;
    else rec.safe += 1;
    state.senders[key] = rec;
  }

  // Online calibration: nudge bias toward correcting this user's error.
  const target = isPhish ? 100 : 0;
  const error = target - modelScore;
  state.bias = Math.max(
    -PN_BIAS_CLAMP,
    Math.min(PN_BIAS_CLAMP, state.bias + PN_LR * error)
  );
  state.count = (state.count || 0) + 1;

  await pnSaveState(state);
  return state;
}

if (typeof window !== "undefined") {
  window.pnAdapt = pnAdapt;
  window.pnRecordFeedback = pnRecordFeedback;
  window.pnLoadState = pnLoadState;
}
