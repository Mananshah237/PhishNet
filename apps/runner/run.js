// PhishNet Open Safely runner (MVP scaffold)
// Usage: node run.js --url https://example.com --job <uuid> --out /out
// Security: default-deny network, allowlist only the target origin when ALLOW_TARGET_ORIGIN=1.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { chromium, devices } = require('playwright');

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return process.argv[i + 1];
}

function sha256File(p) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(p));
  return h.digest('hex');
}

(async () => {
  const url = arg('url');
  const job = arg('job', crypto.randomUUID());
  const outDir = arg('out', '/out');

  if (!url) {
    console.error('Missing --url');
    process.exit(2);
  }

  fs.mkdirSync(outDir, { recursive: true });

  const allowTargetOrigin = process.env.ALLOW_TARGET_ORIGIN === '1';
  const targetOrigin = new URL(url).origin;

  const browser = await chromium.launch({ args: ['--disable-dev-shm-usage'] });

  async function runContext(label, contextOptions) {
    const context = await browser.newContext(contextOptions);

    // Belt-and-suspenders: abort all requests unless allowlisted.
    await context.route('**/*', (route) => {
      const reqUrl = route.request().url();
      try {
        const u = new URL(reqUrl);
        const isHttp = u.protocol === 'http:' || u.protocol === 'https:';
        if (!isHttp) return route.abort();

        if (allowTargetOrigin && u.origin === targetOrigin) {
          return route.continue();
        }
        // Default deny.
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
    artifacts: {
      desktop_png: { path: 'desktop.png', sha256: sha256File(desktop.screenshotPath) },
      mobile_png: { path: 'mobile.png', sha256: sha256File(mobile.screenshotPath) },
      text_txt: { path: 'text.txt', sha256: sha256File(desktop.textPath) },
      iocs_json: { path: 'iocs.json', sha256: sha256File(iocsPath) }
    }
  };

  fs.writeFileSync(path.join(outDir, 'meta.json'), JSON.stringify(meta, null, 2), 'utf8');

  await browser.close();
  console.log(JSON.stringify({ ok: true, job_uuid: job, out: outDir }, null, 2));
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
