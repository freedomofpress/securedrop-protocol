const fs = require('fs');
const { Builder, Capabilities } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const firefox = require('selenium-webdriver/firefox');

const { BenchmarkSpec } = require('./specs');
const { makeTmp } = require('./utils');

function expandFlavors(browserSel, flavorsArg) {
  const wantChromium = browserSel === 'chromium' || browserSel === 'all';
  const wantFirefox = browserSel === 'firefox' || browserSel === 'all';

  const requested = (flavorsArg === 'all')
    ? ['bundled', 'chrome', 'chrome-beta', 'chrome-dev', 'firefox', 'firefox-beta', 'firefox-nightly']
    : flavorsArg.split(',').map((s) => s.trim()).filter(Boolean);

  const out = [];
  if (wantChromium) {
    ['bundled', 'chrome', 'chrome-beta', 'chrome-dev'].forEach((label) => {
      if (requested.includes('all') || requested.includes(label)) out.push({ family: 'chromium', label });
    });
  }
  if (wantFirefox) {
    ['bundled', 'firefox', 'firefox-beta', 'firefox-nightly'].forEach((label) => {
      if (requested.includes('all') || requested.includes(label)) out.push({ family: 'firefox', label });
    });
  }
  return out;
}

function mapFlavorToVersion(family, label) {
  if (family === 'chromium') {
    if (label === 'bundled' || label === 'chrome') return 'stable';
    if (label === 'chrome-beta') return 'beta';
    if (label === 'chrome-dev') return 'dev';
    return null;
  }

  if (label === 'bundled' || label === 'firefox') return 'stable';
  if (label === 'firefox-beta') return 'beta';
  if (label === 'firefox-nightly') return 'nightly';
  return null;
}

async function buildDriver(family, versionLabel, profileDir) {
  if (family === 'chromium') {
    const opts = new chrome.Options()
      .addArguments(
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-extensions',
        `--user-data-dir=${profileDir}`,
        '--remote-debugging-port=0',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--enable-features=WebAssemblySimd',
      );
    let caps = new Capabilities().setBrowserName('chrome');
    if (versionLabel) caps = caps.set('browserVersion', versionLabel);
    return new Builder().withCapabilities(caps).setChromeOptions(opts).build();
  }

  const opts = new firefox.Options();
  opts.addArguments('-headless');
  opts.setProfile(profileDir);

  let caps = new Capabilities().setBrowserName('firefox');
  if (versionLabel) caps = caps.set('browserVersion', versionLabel);
  return new Builder().withCapabilities(caps).setFirefoxOptions(opts).build();
}

async function runSpecOnDriver(driver, baseUrl, spec, timeoutMs = 60_000) {
  const url = baseUrl + spec.toQuery();
  await driver.get(url);

  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const ready = await driver.executeScript('return !!window.benchReady;');
    if (ready) {
      const obj = await driver.executeScript(
        'return window.benchResultsByName && window.benchResultsByName[arguments[0]];',
        spec.name,
      );
      if (obj) return obj; // contains samples_us (or samples_ms fallback)
    }
    await driver.sleep(100);
  }
  throw new Error(`Timeout waiting for payload (bench=${spec.name})`);
}

async function runSpecProfileIsolated(family, versionLabel, baseUrl, spec, iterations) {
  const combined = [];
  for (let i = 0; i < iterations; i++) {
    const tmpProfile = makeTmp(`bench-${family}-${versionLabel || 'stable'}-iter${i}-`);
    let driver;
    try {
      driver = await buildDriver(family, versionLabel, tmpProfile);
      // Force a single-iteration page run
      const oneIter = new BenchmarkSpec(spec.name, { ...spec.params, n: 1 });
      const res = await runSpecOnDriver(driver, baseUrl, oneIter);

      const samplesUs = Array.isArray(res.samples_us)
        ? res.samples_us.map((x) => Math.round(x))
        : Array.isArray(res.samples_ms)
          ? res.samples_ms.map((x) => Math.round(x * 1000))
          : [];

      if (samplesUs.length === 1) {
        combined.push(samplesUs[0]);
      }
    } finally {
      if (driver) await driver.quit();
      try {
        fs.rmSync(tmpProfile, { recursive: true, force: true });
      } catch {
        // ignore cleanup failures
      }
    }
  }
  return combined;
}

module.exports = {
  expandFlavors,
  mapFlavorToVersion,
  buildDriver,
  runSpecOnDriver,
  runSpecProfileIsolated,
};
