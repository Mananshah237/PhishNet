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

    // Treat ALL backend fields (label, risk_score, reasons) as untrusted: build
    // the DOM with textContent rather than interpolating into innerHTML, to
    // prevent XSS from a compromised/spoofed backend response.
    const label = String(result.label || "");
    const score = Number(result.risk_score);
    const scoreText = Number.isFinite(score) ? String(score) : "?";

    const head = document.createElement("div");
    head.className = "pn-panel-head";
    head.style.background = color;
    const headSpan = document.createElement("span");
    headSpan.textContent = `PhishNet: ${label.toUpperCase()} — ${scoreText}/100`;
    const closeBtn = document.createElement("button");
    closeBtn.id = "pn-close";
    closeBtn.title = "Close";
    closeBtn.textContent = "×";
    head.appendChild(headSpan);
    head.appendChild(closeBtn);

    const body = document.createElement("div");
    body.className = "pn-panel-body";
    const ul = document.createElement("ul");
    (Array.isArray(result.reasons) ? result.reasons : []).forEach((r) => {
      const li = document.createElement("li");
      li.textContent = String(r);
      ul.appendChild(li);
    });
    body.appendChild(ul);

    const fb = document.createElement("div");
    fb.className = "pn-feedback";
    const fbLabel = document.createElement("span");
    fbLabel.textContent = "Was this right?";
    const safeBtn = document.createElement("button");
    safeBtn.id = "pn-mark-safe";
    safeBtn.textContent = "Mark safe";
    const phishBtn = document.createElement("button");
    phishBtn.id = "pn-mark-phish";
    phishBtn.textContent = "Mark phishing";
    fb.appendChild(fbLabel);
    fb.appendChild(safeBtn);
    fb.appendChild(phishBtn);
    body.appendChild(fb);

    const fbMsg = document.createElement("div");
    fbMsg.id = "pn-fb-msg";
    fbMsg.className = "pn-fb-msg";
    body.appendChild(fbMsg);

    panel.appendChild(head);
    panel.appendChild(body);
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
      const headers = { "Content-Type": "application/json" };
      if (cfg.apiKey) headers["X-API-Key"] = cfg.apiKey;
      const resp = await fetch(`${cfg.backendUrl.replace(/\/$/, "")}/analyze`, {
        method: "POST",
        headers,
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
