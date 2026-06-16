async function init() {
  const cfg = await pnGetConfig();
  document.getElementById("backend").textContent = cfg.backendUrl;

  const out = await chrome.storage.local.get("pn_personalization");
  const s = out.pn_personalization || { count: 0 };
  document.getElementById("learn").textContent =
    `Personalization: learned from ${s.count || 0} corrections`;

  try {
    const r = await fetch(`${cfg.backendUrl.replace(/\/$/, "")}/health`);
    document.getElementById("status").textContent = r.ok ? "connected" : "backend error";
    document.getElementById("status").style.color = r.ok ? "#1a7f37" : "#c0271e";
  } catch {
    document.getElementById("status").textContent = "not reachable";
    document.getElementById("status").style.color = "#c0271e";
  }
}

document.getElementById("opts").onclick = () => chrome.runtime.openOptionsPage();
init();
