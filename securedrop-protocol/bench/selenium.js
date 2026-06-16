const fs = require('fs');
const { Builder, Capabilities } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const firefox = require('selenium-webdriver/firefox');

const { BenchmarkSpec } = require('./specs');
const { logInfo, logWarn, makeTmp, withTimeout } = require('./utils');

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

// Returns { driver, service }. We build the driver via Driver.createSession with
// an explicitly-constructed service (instead of `new Builder().build()`) so we
// keep a reference to the underlying chromedriver/geckodriver process. That lets
// us force-kill it (and its browser) if driver.quit() hangs on a wedged session —
// the Builder hides the service, leaving no way to reap a stuck driver. Binary/
// version resolution (Selenium Manager) still happens inside createSession.
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
    if (versionLabel) opts.set('browserVersion', versionLabel);
    const service = new chrome.ServiceBuilder().build();
    return startSession(() => chrome.Driver.createSession(opts, service), service);
  }

  const opts = new firefox.Options();
  opts.addArguments('-headless');
  opts.setProfile(profileDir);
  if (versionLabel) opts.set('browserVersion', versionLabel);
  const service = new firefox.ServiceBuilder().build();
  return startSession(() => firefox.Driver.createSession(opts, service), service);
}

// createSession starts the service before it may throw (e.g. "Failed to read
// marionette port"). If it throws, kill the now-running service so we don't leak
// a driver/browser process on every failed/retried attempt.
async function startSession(create, service) {
  try {
    const driver = await create();
    return { driver, service };
  } catch (e) {
    try {
      if (service.isRunning()) await service.kill();
    } catch {
      // best effort
    }
    throw e;
  }
}

const QUIT_TIMEOUT_MS = 15_000;
const KILL_TIMEOUT_MS = 10_000;

// Tear down a { driver, service } handle without ever hanging the run. A clean
// driver.quit() stops the service via its onQuit hook; but if the session is
// wedged, quit() never returns — so we bound it and then force-kill the still-
// running service, which terminates the driver process and its browser and frees
// the WebDriver sockets that would otherwise keep Node alive at exit.
async function disposeDriver(handle) {
  if (!handle) return;
  const { driver, service } = handle;

  if (driver) {
    try {
      await withTimeout(driver.quit(), QUIT_TIMEOUT_MS, 'driver.quit()');
    } catch (e) {
      logWarn(`driver.quit() did not complete (${e.message}); force-killing driver`);
    }
  }

  if (service && service.isRunning()) {
    try {
      await withTimeout(service.kill(), KILL_TIMEOUT_MS, 'service.kill()');
    } catch (e) {
      logWarn(`Could not kill driver service (browser may be orphaned): ${e.message}`);
    }
  }
}

async function runSpecOnDriver(driver, baseUrl, spec, timeoutMs = 60_000) {
  const url = baseUrl + spec.toQuery();

  const run = (async () => {
    try {
      await driver.manage().setTimeouts({ pageLoad: timeoutMs, script: timeoutMs });
    } catch {
      // not all drivers honor setTimeouts; ignore
    }

    await driver.get(url);

    for (;;) {
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
  })();

  return withTimeout(run, timeoutMs, `payload bench=${spec.name}`);
}

const PROFILE_MAX_ATTEMPTS = 3;
const PROFILE_ITER_TIMEOUT_MS = 120_000;

async function runSpecProfileIsolated(
  family,
  versionLabel,
  baseUrl,
  spec,
  iterations,
  { attempts = PROFILE_MAX_ATTEMPTS, iterTimeoutMs = PROFILE_ITER_TIMEOUT_MS } = {},
) {
  const combined = [];
  for (let i = 0; i < iterations; i++) {
    logInfo(
      `Profile ${i + 1}/${iterations} for ${family} ${versionLabel || 'stable'} (${spec.name})`,
    );
    for (let attempt = 1; ; attempt++) {
      const tmpProfile = makeTmp(`bench-${family}-${versionLabel || 'stable'}-iter${i}-`);
      let handle;
      try {
        const samplesUs = await withTimeout(
          (async () => {
            handle = await buildDriver(family, versionLabel, tmpProfile);
            // Force a single-iteration page run
            const oneIter = new BenchmarkSpec(spec.name, { ...spec.params, n: 1 });
            const res = await runSpecOnDriver(handle.driver, baseUrl, oneIter, iterTimeoutMs);

            return Array.isArray(res.samples_us)
              ? res.samples_us.map((x) => Math.round(x))
              : Array.isArray(res.samples_ms)
                ? res.samples_ms.map((x) => Math.round(x * 1000))
                : [];
          })(),
          iterTimeoutMs + 5_000,
          `profile iter ${i + 1} ${family} (${spec.name})`,
        );

        if (samplesUs.length === 1) {
          combined.push(samplesUs[0]);
        }
        break;
      } catch (e) {
        if (attempt >= attempts) throw e;
        logWarn(
          `Retrying profile ${i + 1} for ${family} (${spec.name}), attempt ${attempt + 1}/${attempts}: ${e.message}`,
        );
      } finally {
        await disposeDriver(handle);
        try {
          fs.rmSync(tmpProfile, { recursive: true, force: true });
        } catch {
          // ignore cleanup failures
        }
      }
    }
  }
  return combined;
}

module.exports = {
  expandFlavors,
  mapFlavorToVersion,
  buildDriver,
  disposeDriver,
  runSpecOnDriver,
  runSpecProfileIsolated,
};
