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

    // Default deny all requests; optionally allow only the exact target origin.
    await context.route('**/*', (route) => {
      const reqUrl = route.request().url();
      try {
        const u = new URL(reqUrl);
        const isHttp = u.protocol === 'http:' || u.protocol === 'https:';
        if (!isHttp) return route.abort();

        // Block obvious private/localhost targets even if allowTargetOrigin is enabled.
        const host = (u.hostname || '').toLowerCase();
        if (host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local')) return route.abort();
        if (looksLikeIp(host)) {
          // very rough private-range block
          if (host.startsWith('10.') || host.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) {
            return route.abort();
          }
        }

        if (allowTargetOrigin && u.origin === targetOrigin) {
          return route.continue();
        }
        return route.abort();
      } catch {
        return route.abort();
      }
    });

    const page = await context.newPage();

    let navError = null;
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.waitForTimeout(1000);
    } catch (e) {
      navError = String(e);
    }

    const screenshotPath = path.join(outDir, `${label}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });

    const textPath = path.join(outDir, 'text.txt');
    const text = await page.evaluate(() => document.body?.innerText?.slice(0, 20000) || '');
    fs.writeFileSync(textPath, text, 'utf8');

    await context.close();
    return { screenshotPath, textPath, navError };
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
      nav_errors: { desktop: desktop.navError, mobile: mobile.navError }
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
