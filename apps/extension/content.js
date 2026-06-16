// Gmail content script: scrape the open email, send it to the PhishNet backend,
// show a verdict panel, and learn from the user's feedback.
//
// This MVP reads the email from the Gmail DOM — no OAuth, no Google API quota,
// nothing to verify, so the extension is free to ship and use. The robust
// upgrade path (more resilient, store-friendly) is the Gmail API via
// chrome.identity OAuth (scope gmail.readonly + messages.get?format=raw); that
// requires Google verification + a CASA security assessment, so it is a later
// step, not needed for a working free build.

(function () {
  const BTN_ID = "pn-scan-btn";
  const PANEL_ID = "pn-panel";

  function scrapeOpenEmail() {
    const subjectEl = document.querySelector("h2.hP");
    const senderEl = document.querySelector("span.gD");
    // Gmail renders each message body in div.a3s; take the last (newest) open one.
    const bodyEls = document.querySelectorAll("div.a3s");
    const bodyEl = bodyEls.length ? bodyEls[bodyEls.length - 1] : null;
    if (!subjectEl && !bodyEl) return null;

    const links = bodyEl
      ? Array.from(bodyEl.querySelectorAll("a[href]"))
          .map((a) => a.href)
          .filter((h) => h && h.startsWith("http"))
      : [];

    return {
      subject: subjectEl ? subjectEl.innerText.trim() : "",
      from_addr: senderEl ? (senderEl.getAttribute("email") || senderEl.innerText).trim() : "",
      body_text: bodyEl ? bodyEl.innerText.trim() : "",
      body_html: bodyEl ? bodyEl.innerHTML : "",
      urls: Array.from(new Set(links)).slice(0, 50),
    };
  }

  function colorFor(label) {
    if (label === "phishing") return "#c0271e";
    if (label === "suspicious") return "#b8860b";
    return "#1a7f37";
  }

  function removePanel() {
    const old = document.getElementById(PANEL_ID);
    if (old) old.remove();
  }

  function renderPanel(result, meta, modelScore) {
    removePanel();
    const panel = document.createElement("div");
    panel.id = PANEL_ID;
    const color = colorFor(result.label);
    panel.innerHTML = `
      <div class="pn-panel-head" style="background:${color}">
        <span>PhishNet: ${result.label.toUpperCase()} — ${result.risk_score}/100</span>
        <button id="pn-close" title="Close">×</button>
      </div>
      <div class="pn-panel-body">
        <ul>${result.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
        <div class="pn-feedback">
          <span>Was this right?</span>
          <button id="pn-mark-safe">Mark safe</button>
          <button id="pn-mark-phish">Mark phishing</button>
        </div>
        <div id="pn-fb-msg" class="pn-fb-msg"></div>
      </div>`;
    document.body.appendChild(panel);

    document.getElementById("pn-close").onclick = removePanel;
    document.getElementById("pn-mark-safe").onclick = () =>
      feedback(meta, modelScore, "safe");
    document.getElementById("pn-mark-phish").onclick = () =>
      feedback(meta, modelScore, "phishing");
  }

  async function feedback(meta, modelScore, label) {
    const state = await window.pnRecordFeedback(meta, modelScore, label);
    const msg = document.getElementById("pn-fb-msg");
    if (msg)
      msg.textContent = `Thanks — PhishNet adapted to you (${state.count} corrections learned).`;
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = String(s);
    return d.innerHTML;
  }

  async function runScan() {
    const cfg = await window.pnGetConfig();
    const meta = scrapeOpenEmail();
    if (!meta) {
      renderPanel(
        { label: "benign", risk_score: 0, reasons: ["Open an email first, then scan."] },
        { from: "" },
        0
      );
      return;
    }

    renderPanel(
      { label: "suspicious", risk_score: 0, reasons: ["Scanning…"] },
      meta,
      0
    );

    try {
      const resp = await fetch(`${cfg.backendUrl.replace(/\/$/, "")}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...meta, method: cfg.method }),
      });
      if (!resp.ok) throw new Error(`backend ${resp.status}`);
      const raw = await resp.json();
      const modelScore = raw.risk_score;
      const shown = cfg.personalize ? await window.pnAdapt(raw, meta) : raw;
      renderPanel(shown, meta, modelScore);
    } catch (e) {
      renderPanel(
        {
          label: "suspicious",
          risk_score: 0,
          reasons: [
            `Could not reach the PhishNet backend at ${cfg.backendUrl}.`,
            "Start the backend, or set its URL in the extension options.",
          ],
        },
        meta,
        0
      );
    }
  }

  function ensureButton() {
    if (document.getElementById(BTN_ID)) return;
    const btn = document.createElement("button");
    btn.id = BTN_ID;
    btn.textContent = "🛡 Scan email";
    btn.title = "Scan the open email with PhishNet";
    btn.onclick = runScan;
    document.body.appendChild(btn);
  }

  // Gmail is a SPA; keep the button present as the view changes.
  ensureButton();
  const obs = new MutationObserver(() => ensureButton());
  obs.observe(document.body, { childList: true, subtree: true });
})();
