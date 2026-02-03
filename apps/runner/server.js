// PhishNet Open Safely runner (HTTP service)
// POST /render { url, job, outSubdir, allowTargetOrigin }
// Writes artifacts to /out/<outSubdir>/<job>/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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

async function renderOnce(url, job, outDir, allowTargetOrigin) {
  const targetOrigin = new URL(url).origin;

  const browser = await chromium.launch({ args: ['--disable-dev-shm-usage'] });

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

        // Block obvious private/localhost targets even if allowTargetOrigin is enabled.
        const host = (u.hostname || '').toLowerCase();
        if (host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local')) {
          net.blocked++;
          net.blockedHosts.add(host);
          return route.abort();
        }
        if (looksLikeIp(host)) {
          // very rough private-range block
          if (host.startsWith('10.') || host.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) {
            net.blocked++;
            net.blockedHosts.add(host);
            return route.abort();
          }
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

  const jobId = job || crypto.randomUUID();
  const sub = outSubdir || 'open-safely';

  const outRoot = process.env.OUT_DIR || '/out';
  const outDir = path.join(outRoot, sub, jobId);
  fs.mkdirSync(outDir, { recursive: true });

  try {
    const meta = await renderOnce(url, jobId, outDir, !!allowTargetOrigin);
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
