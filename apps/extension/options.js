async function load() {
  const cfg = await pnGetConfig();
  document.getElementById("backendUrl").value = cfg.backendUrl;
  document.getElementById("method").value = cfg.method;
  document.getElementById("personalize").checked = cfg.personalize;
  showStats();
}

async function showStats() {
  const out = await chrome.storage.local.get("pn_personalization");
  const s = out.pn_personalization || { senders: {}, bias: 0, count: 0 };
  const senders = Object.keys(s.senders || {}).length;
  document.getElementById("stats").textContent =
    `Learned from ${s.count || 0} corrections · ${senders} known senders · calibration bias ${Math.round(s.bias || 0)}`;
}

document.getElementById("save").onclick = async () => {
  await pnSetConfig({
    backendUrl: document.getElementById("backendUrl").value.trim() || PN_DEFAULTS.backendUrl,
    method: document.getElementById("method").value.trim() || PN_DEFAULTS.method,
    personalize: document.getElementById("personalize").checked,
  });
  const el = document.getElementById("saved");
  el.textContent = "Saved";
  setTimeout(() => (el.textContent = ""), 1500);
};

document.getElementById("reset").onclick = async () => {
  await chrome.storage.local.remove("pn_personalization");
  showStats();
};

load();
