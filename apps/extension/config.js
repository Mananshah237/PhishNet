// Shared config + storage helpers for PhishNet.
// The backend URL is configurable so the same extension works against a local
// instance (default) or a hosted one, with no code change.

const PN_DEFAULTS = {
  backendUrl: "http://localhost:8002",
  method: "heuristic,bert", // engines to request; LLM is opt-in (slow/costly)
  personalize: true,
  // API key for the PhishNet backend. The backend requires an API key on all
  // data endpoints (sent as the X-API-Key header). Set this in the extension
  // Options page to the key your operator provisioned. Leave blank only when the
  // backend runs with PHISHNET_AUTH_DISABLED=1 (local development).
  apiKey: "",
};

async function pnGetConfig() {
  const stored = await chrome.storage.sync.get(PN_DEFAULTS);
  return { ...PN_DEFAULTS, ...stored };
}

async function pnSetConfig(partial) {
  await chrome.storage.sync.set(partial);
}

// Expose for non-module content-script scope.
if (typeof window !== "undefined") {
  window.PN_DEFAULTS = PN_DEFAULTS;
  window.pnGetConfig = pnGetConfig;
  window.pnSetConfig = pnSetConfig;
}
