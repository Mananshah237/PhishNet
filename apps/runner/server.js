// PhishNet Open Safely runner (HTTP service)
// POST /render { url, job, outSubdir, allowTargetOrigin }
// Writes artifacts to /out/<outSubdir>/<job>/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const netModule = require('net');
const express = require('express');
const { chromium, devices } = require('playwright');

function sha256File(p) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(p));
  return h.digest('hex');
}

function looksLikeIp(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

// ---- SSRF guard helpers -----------------------------------------------------
// Classify an IP literal as private/loopback/link-local/metadata/reserved so we
// can block requests that would let a sandboxed page reach internal services.

function isBlockedIPv4(ip) {
  const parts = ip.split('.').map((n) => parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true; // malformed → block
  }
  const [a, b] = parts;
  if (a === 0) return true;                         // 0.0.0.0/8 ("this host")
  if (a === 10) return true;                        // 10.0.0.0/8 private
  if (a === 127) return true;                       // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;          // 169.254.0.0/16 link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true;          // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true;// 100.64.0.0/10 carrier-grade NAT
  if (a === 192 && b === 0) return true;            // 192.0.0.0/24 + 192.0.2.0/24 reserved
  if (a >= 224) return true;                        // 224.0.0.0/4 multicast + 240/4 reserved
  return false;
}

function isBlockedIPv6(ip) {
  let v = ip.toLowerCase();
  // Strip zone id and brackets if present.
  v = v.replace(/^\[|\]$/g, '').split('%')[0];
  if (v === '::1' || v === '::') return true;       // loopback / unspecified
  if (v.startsWith('fe80')) return true;            // link-local fe80::/10
  if (v.startsWith('fc') || v.startsWith('fd')) return true; // unique-local fc00::/7
  if (v.startsWith('ff')) return true;              // multicast ff00::/8
  // IPv4-mapped (::ffff:a.b.c.d) → validate the embedded IPv4.
  const mapped = v.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return isBlockedIPv4(mapped[1]);
  return false;
}

function isBlockedIp(ip) {
  const fam = netModule.isIP(ip);
  if (fam === 4) return isBlockedIPv4(ip);
  if (fam === 6) return isBlockedIPv6(ip);
  return true; // not a valid IP literal → block
}

// Resolve a hostname and ensure EVERY resolved address is public. Returns
// { ok, reason }. Defeats DNS-rebinding by validating the actual resolved IPs
// (the page is then routed through these checks again on every request).
async function hostResolvesPublic(host) {
  const h = (host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return { ok: false, reason: 'empty host' };
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.localhost')) {
    return { ok: false, reason: 'localhost' };
  }
  // Literal IP host: validate directly.
  if (netModule.isIP(h)) {
    return isBlockedIp(h)
      ? { ok: false, reason: `blocked ip ${h}` }
      : { ok: true, addresses: [h] };
  }
  let addrs;
  try {
    addrs = await dns.lookup(h, { all: true });
  } catch (e) {
    return { ok: false, reason: `dns lookup failed: ${String(e)}` };
  }
  if (!addrs.length) return { ok: false, reason: 'no addresses' };
  for (const a of addrs) {
    if (isBlockedIp(a.address)) {
      return { ok: false, reason: `resolves to private ip ${a.address}` };
    }
  }
  // Return the validated public addresses so the caller can PIN the connection
  // to them (defeats DNS rebinding: the resolver is not consulted again).
  return { ok: true, addresses: addrs.map((a) => a.address) };
}

// Build a Chromium --host-resolver-rules value that pins the target hostname to
// an already-validated public IP, so Chromium cannot be DNS-rebound to an
// internal address between pre-flight validation and the actual connection.
// Returns null when there is nothing to pin (IP-literal host or no addresses).
function buildResolverPin(host, addresses) {
  if (!host || !Array.isArray(addresses) || !addresses.length) return null;
  if (netModule.isIP(host)) return null; // literal IP — no resolution to rebind
  // Prefer an IPv4 address (simplest MAP syntax); fall back to IPv6 in brackets.
  const ipv4 = addresses.find((a) => netModule.isIP(a) === 4);
  const chosen = ipv4 || addresses[0];
  const mapTarget = netModule.isIP(chosen) === 6 ? `[${chosen}]` : chosen;
  return `MAP ${host} ${mapTarget}`;
}

async function renderOnce(url, job, outDir, allowTargetOrigin, resolverPin) {
  const targetOrigin = new URL(url).origin;

  const launchArgs = ['--disable-dev-shm-usage'];
  if (resolverPin) {
    // Pin DNS for the target host. Anything not matched here still falls through
    // to the per-request route() default-deny, so no other host is reachable.
    launchArgs.push(`--host-resolver-rules=${resolverPin}`);
  }
  const browser = await chromium.launch({ args: launchArgs });

  async function runContext(label, contextOptions) {
    const context = await browser.newContext(contextOptions);

    const net = {
      allowed: 0,
      blocked: 0,
      blockedHosts: new Set()
    };

    // Default deny all requests; optionally allow only the exact target origin.
    await context.route('**/*', (route) => {
      const reqUrl = route.request().url();
      try {
        const u = new URL(reqUrl);
        const isHttp = u.protocol === 'http:' || u.protocol === 'https:';
        if (!isHttp) {
          net.blocked++;
          return route.abort();
        }

        // Block private/loopback/link-local/metadata targets even if
        // allowTargetOrigin is enabled. Covers IPv4, IPv6 (::1, fc00::/7,
        // fe80::/10), 169.254.0.0/16 (cloud metadata), 100.64.0.0/10, etc.
        const host = (u.hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
        if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.localhost')) {
          net.blocked++;
          net.blockedHosts.add(host);
          return route.abort();
        }
        if (netModule.isIP(host) && isBlockedIp(host)) {
          net.blocked++;
          net.blockedHosts.add(host);
          return route.abort();
        }

        if (allowTargetOrigin && u.origin === targetOrigin) {
          net.allowed++;
          return route.continue();
        }
        net.blocked++;
        net.blockedHosts.add(host);
        return route.abort();
      } catch {
        net.blocked++;
        return route.abort();
      }
    });

    const page = await context.newPage();

    let navError = null;
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.waitForTimeout(800);
    } catch (e) {
      navError = String(e);
    }

    // Try to extract visible text; if empty, fall back to stripping HTML.
    let text = '';
    try {
      text = await page.evaluate(() => document.body?.innerText?.slice(0, 20000) || '');
      if (!text) {
        const html = await page.content();
        text = html
          .replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/<style[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 20000);
      }
    } catch {
      text = '';
    }

    // Inject a policy banner so screenshots never look "broken" even when content is blocked.
    try {
      const banner = {
        title: 'PhishNet Open Safely (Screenshot-Only)',
        policy: allowTargetOrigin ? 'Allow target origin ONLY' : 'Default-deny (no network)',
        allowed: net.allowed,
        blocked: net.blocked,
        blockedHosts: Array.from(net.blockedHosts).slice(0, 8)
      };

      await page.addStyleTag({
        content: `
          .phishnet-banner{position:fixed;top:0;left:0;right:0;z-index:2147483647;
            padding:10px 12px;font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial;
            background:rgba(15,23,42,0.95);color:#fff;border-bottom:1px solid rgba(255,255,255,0.18)}
          .phishnet-banner small{color:rgba(229,231,235,0.85)}
          .phishnet-banner code{color:#e5e7eb}
          body{padding-top:58px !important;}
        `
      });

      await page.evaluate((b) => {
        const div = document.createElement('div');
        div.className = 'phishnet-banner';
        div.innerHTML = `<div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;">
          <div>
            <div style="font-weight:800;">${b.title}</div>
            <small>Policy: <code>${b.policy}</code> • Allowed: <code>${b.allowed}</code> • Blocked: <code>${b.blocked}</code></small>
          </div>
          <small style="max-width:55%;text-align:right;">${b.blockedHosts?.length ? ('Blocked hosts: ' + b.blockedHosts.map(h=>`<code>${h}</code>`).join(' ')) : ''}</small>
        </div>`;
        document.documentElement.appendChild(div);
      }, banner);
    } catch {
      // ignore banner failures
    }

    const screenshotPath = path.join(outDir, `${label}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });

    const textPath = path.join(outDir, 'text.txt');
    fs.writeFileSync(textPath, text || '', 'utf8');

    await context.close();
    return { screenshotPath, textPath, navError, net: { allowed: net.allowed, blocked: net.blocked, blockedHosts: Array.from(net.blockedHosts) } };
  }

  const desktop = await runContext('desktop', { viewport: { width: 1280, height: 720 } });
  const iPhone = devices['iPhone 13'];
  const mobile = await runContext('mobile', { ...iPhone });

  const iocs = {
    target_url: url,
    target_origin: targetOrigin,
    defanged_domains: [targetOrigin.replace(/^https?:\/\//, '').replace(/\./g, '[.]')],
    notes: {
      allow_target_origin: allowTargetOrigin,
      nav_errors: { desktop: desktop.navError, mobile: mobile.navError },
      network: {
        desktop: desktop.net,
        mobile: mobile.net
      }
    }
  };

  const iocsPath = path.join(outDir, 'iocs.json');
  fs.writeFileSync(iocsPath, JSON.stringify(iocs, null, 2), 'utf8');

  const meta = {
    job_uuid: job,
    created_at: new Date().toISOString(),
    policy: {
      allow_target_origin: allowTargetOrigin,
      default_deny: true
    },
    artifacts: {
      desktop_png: { path: 'desktop.png', sha256: sha256File(desktop.screenshotPath) },
      mobile_png: { path: 'mobile.png', sha256: sha256File(mobile.screenshotPath) },
      text_txt: { path: 'text.txt', sha256: sha256File(desktop.textPath) },
      iocs_json: { path: 'iocs.json', sha256: sha256File(iocsPath) }
    }
  };

  fs.writeFileSync(path.join(outDir, 'meta.json'), JSON.stringify(meta, null, 2), 'utf8');

  await browser.close();
  return meta;
}

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/render', async (req, res) => {
  const { url, job, outSubdir, allowTargetOrigin } = req.body || {};
  if (!url) return res.status(400).json({ error: 'missing url' });

  // SSRF defense in depth:
  //  1. Only http(s) URLs.
  //  2. Pre-flight: the target host must resolve exclusively to public IPs.
  //  3. PIN the connection to those validated IPs via --host-resolver-rules, so
  //     Chromium cannot be DNS-rebound to an internal address at connect time.
  //  4. The per-request route() guard default-denies every origin except the
  //     (pinned) target, and blocks any IP-literal in private/metadata ranges.
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return res.status(400).json({ error: 'invalid url' });
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return res.status(400).json({ error: 'only http/https URLs are allowed' });
  }
  const guard = await hostResolvesPublic(parsed.hostname);
  if (!guard.ok) {
    return res.status(400).json({ error: `blocked target (SSRF guard): ${guard.reason}` });
  }
  const resolverPin = buildResolverPin(parsed.hostname, guard.addresses);

  const jobId = job || crypto.randomUUID();
  const sub = outSubdir || 'open-safely';

  const outRoot = process.env.OUT_DIR || '/out';
  const outDir = path.join(outRoot, sub, jobId);
  fs.mkdirSync(outDir, { recursive: true });

  try {
    const meta = await renderOnce(url, jobId, outDir, !!allowTargetOrigin, resolverPin);
    res.json({ ok: true, job_id: jobId, out_dir: outDir, meta });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e), job_id: jobId, out_dir: outDir });
  }
});

const port = process.env.PORT || 7070;
app.listen(port, '0.0.0.0', () => {
  // eslint-disable-next-line no-console
  console.log(`phishnet-runner listening on ${port}`);
});
