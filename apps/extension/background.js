// Minimal service worker. Seeds default config on install so the extension
// works immediately against a local backend.

const DEFAULTS = {
  backendUrl: "http://localhost:8002",
  method: "heuristic,bert",
  personalize: true,
};

chrome.runtime.onInstalled.addListener(async () => {
  const cur = await chrome.storage.sync.get(DEFAULTS);
  await chrome.storage.sync.set({ ...DEFAULTS, ...cur });
});
