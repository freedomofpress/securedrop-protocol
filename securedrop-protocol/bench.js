#!/usr/bin/env node
/* bench.js — native + Selenium Firefox/Chrome flavors, finds best performers.
 *
 * Usage:
 *   node bench.js -n 500
 *   node bench.js --browser chromium -n 250
 *   node bench.js --browser all --native off -n 100
 *   node bench.js --flavors bundled,firefox,chrome -n 200
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// --- Selenium imports ---
const { Builder, Capabilities } = require('selenium-webdriver');
const chrome  = require('selenium-webdriver/chrome');
const firefox = require('selenium-webdriver/firefox');

// -------- CLI --------
function parseArgs(argv) {
  let iterations = 100;
  let browserSel = 'all';          // chromium|firefox|all|none (none disables browsers)
  let nativeSel = 'on';            // on|off
  let flavorsArg = 'all';          // all or comma list among: bundled,chrome,chrome-beta,chrome-dev,firefox,firefox-beta,firefox-nightly
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if ((a === '-n' || a === '--iterations') && i + 1 < argv.length) {
      iterations = parseInt(argv[++i], 10);
      if (!Number.isFinite(iterations) || iterations <= 0) {
        console.error(`Invalid iterations: ${argv[i]}`); process.exit(1);
      }
    } else if (a === '--browser' && i + 1 < argv.length) {
      browserSel = argv[++i];
      if (!['chromium', 'firefox', 'all', 'none'].includes(browserSel)) {
        console.error(`Unknown --browser: ${browserSel}`); process.exit(1);
      }
    } else if (a === '--native' && i + 1 < argv.length) {
      nativeSel = argv[++i];
      if (!['on', 'off'].includes(nativeSel)) {
        console.error(`--native must be on|off`); process.exit(1);
      }
    } else if (a === '--flavors' && i + 1 < argv.length) {
      flavorsArg = argv[++i];
    } else {
      console.error(`Unknown arg: ${a}`);
      console.error('Usage: node bench.js [--browser chromium|firefox|all|none] [--native on|off] [--flavors all|comma,list] [-n N]');
      process.exit(1);
    }
  }
  return { iterations, browserSel, nativeSel, flavorsArg };
}

// -------- Server (COOP/COEP) --------
function startServer(root) {
  return new Promise(resolve => {
    const server = http.createServer((req, res) => {
      const reqPath = req.url === '/' ? '/www/index.html' : req.url;
      const filePath = path.join(root, reqPath);

      // COOP/COEP: precise timers & SAB-capable
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
      res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
      res.setHeader('Timing-Allow-Origin', '*');

      fs.readFile(filePath, (err, data) => {
        if (err) { res.statusCode = 404; res.end('Not found'); return; }
        const ext = path.extname(filePath).toLowerCase();
        const types = {
          '.html': 'text/html; charset=utf-8',
          '.js':   'application/javascript; charset=utf-8',
          '.mjs':  'application/javascript; charset=utf-8',
          '.wasm': 'application/wasm',
          '.json': 'application/json; charset=utf-8',
          '.css':  'text/css; charset=utf-8',
        };
        res.setHeader('Content-Type', types[ext] || 'application/octet-stream');
        res.end(data);
      });
    }).listen(0, () => resolve(server));
  });
}

// -------- Native runner --------
function parseNativeOutput(text) {
  // Expects:
  // bench: encrypt
  // iterations: 1000
  // total: 123.456 ms
  // avg:   123.456 µs/iter
  const lines = text.split(/\r?\n/);
  const out = {};
  let current = null;
  for (const line of lines) {
    const b = line.match(/^bench:\s*(\w+)/);
    if (b) { current = b[1]; if (!out[current]) out[current] = {}; continue; }
    if (!current) continue;
    const m1 = line.match(/^iterations:\s*(\d+)/);
    if (m1) { out[current].iterations = parseInt(m1[1], 10); continue; }
    const m2 = line.match(/^total:\s*([\d.]+)\s*ms/);
    if (m2) { out[current].totalMs = parseFloat(m2[1]); continue; }
    const m3 = line.match(/^avg:\s*([\d.]+)\s*µs\/iter/);
    if (m3) { out[current].avgUs = parseFloat(m3[1]); continue; }
  }
  return out;
}

function runNative(iterations) {
  const modes = ['encrypt', 'decrypt', 'fetch', 'submit'];
  const results = {};
  for (const m of modes) {
    const proc = spawnSync(
      'cargo',
      ['bench', '--bench', 'manual', '--', m, '-n', String(iterations)],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    if (proc.status !== 0) {
      console.error(`[native ${m}] failed:\n${proc.stderr.toString()}\n${proc.stdout.toString()}`);
      process.exit(proc.status || 1);
    }
    const parsed = parseNativeOutput(proc.stdout.toString());
    const key = (m === 'submit') ? 'submit_bench' : `${m}_bench`;
    let rec = parsed[m] || parsed[Object.keys(parsed)[0]];
    if (!rec) { console.error(`[native ${m}] could not parse output`); process.exit(1); }
    if (!rec.iterations) rec.iterations = iterations;
    results[key] = rec;
  }
  return results;
}

// -------- Selenium helpers --------
function makeTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Map our "flavors" to Selenium "browserVersion" labels.
// Chrome/Chromium: stable|beta|dev|canary
// Firefox: stable (default)|beta|nightly
function mapFlavorToVersion(family, label) {
  if (family === 'chromium') {
    if (label === 'bundled' || label === 'chrome') return 'stable';
    if (label === 'chrome-beta') return 'beta';
    if (label === 'chrome-dev')  return 'dev';
    return null;
  } else {
    if (label === 'bundled' || label === 'firefox') return 'stable';
    if (label === 'firefox-beta')    return 'beta';
    if (label === 'firefox-nightly') return 'nightly';
    return null;
  }
}

async function buildDriver(family, versionLabel, profileDir) {
  if (family === 'chromium') {
    const opts = new chrome.Options();
    opts.addArguments(
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-extensions',
      `--user-data-dir=${profileDir}`,
      '--remote-debugging-port=0',
      // needed when running as root / in CI containers
      '--no-sandbox',
      '--disable-dev-shm-usage',
      // wasm perf toggles
      '--enable-features=WebAssemblySimd'
    );
    let caps = new Capabilities().setBrowserName('chrome');
    if (versionLabel) caps = caps.set('browserVersion', versionLabel); // stable|beta|dev|canary
    return await new Builder().withCapabilities(caps).setChromeOptions(opts).build();
  }

  // Firefox: fresh temp profile dir + headless via CLI arg (works on all versions)
  const ffProfileDir = profileDir || makeTmpDir('bench-firefox-');
  const opts = new firefox.Options();
  opts.addArguments('-headless'); // avoid .headless() chaining issues on some builds
  opts.setProfile(ffProfileDir);
  opts.setPreference('javascript.options.wasm', true);
  opts.setPreference('javascript.options.wasm_simd', true);
  opts.setPreference('javascript.options.wasm_relaxed_simd', true);
  opts.setPreference('javascript.options.wasm_threads', true);

  let caps = new Capabilities().setBrowserName('firefox');
  if (versionLabel) caps = caps.set('browserVersion', versionLabel);   // stable|beta|nightly
  const driver = await new Builder().withCapabilities(caps).setFirefoxOptions(opts).build();

  // Keep profile for cleanup
  driver.__ffProfileDir = ffProfileDir;
  return driver;
}

async function ensureExports(driver) {
  await driver.wait(async () => {
    return await driver.executeScript(`
      return ['encrypt_bench','decrypt_bench','fetch_bench','submit_bench']
        .every(n => typeof window[n] === 'function');
    `);
  }, 30000);
}

async function runOne(driver, iterations, name) {
  // Warm-up
  await driver.executeScript(`window;`, name);
  const res = await driver.executeScript(`
    const name = arguments[0], iters = arguments[1];
    const t0 = performance.now();
    window[name](iters);
    const totalMs = performance.now() - t0;
    return { totalMs, avgUs: (totalMs * 1000) / iters };
  `, name, iterations);
  return { ...res, iterations };
}

async function runFlavor(flavor, iterations, url) {
  const versionLabel = mapFlavorToVersion(flavor.family, flavor.label);
  const tmpProfile =
    (flavor.family === 'chromium')
      ? makeTmpDir(`bench-chrome-${flavor.label}-`)
      : makeTmpDir(`bench-firefox-${flavor.label}-`);

  let driver;
  try {
    driver = await buildDriver(flavor.family, versionLabel, tmpProfile);
    await driver.get(url);

    const caps = await driver.getCapabilities();
    const version = caps.get('browserVersion') || 'unknown';

    const coi = await driver.executeScript('return !!globalThis.crossOriginIsolated;');
    if (!coi) {
      console.warn(`[${flavor.family}:${flavor.label}] crossOriginIsolated=false; timers may be coarse.`);
    }

    await ensureExports(driver);

    const results = {};
    for (const name of ['encrypt_bench', 'decrypt_bench', 'fetch_bench', 'submit_bench']) {
      results[name] = await runOne(driver, iterations, name);
    }

    return { flavor, version, coi, results };
  } finally {
    if (driver) await driver.quit();
    // Clean up temp profiles
    try { fs.rmSync(tmpProfile, { recursive: true, force: true }); } catch {}
    if (driver && driver.__ffProfileDir && driver.__ffProfileDir !== tmpProfile) {
      try { fs.rmSync(driver.__ffProfileDir, { recursive: true, force: true }); } catch {}
    }
  }
}

// -------- Tables / printing --------
function padRight(s, n) { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); }
function padLeft(s, n)  { s = String(s); return ' '.repeat(Math.max(0, n - s.length)) + s; }

function makeTable(rows, headers, aligns = []) {
  const cols = headers.length;
  const widths = Array(cols).fill(0);
  for (let c = 0; c < cols; c++) {
    widths[c] = Math.max(headers[c].length, ...rows.map(r => String(r[c]).length));
  }
  const cell = (s, i) => (aligns[i] === 'right' ? padLeft(s, widths[i]) : padRight(s, widths[i]));
  console.log(headers.map((h, i) => cell(h, i)).join('  '));
  console.log('-'.repeat(widths.reduce((a, b) => a + b, 0) + 2 * (cols - 1)));
  for (const r of rows) console.log(r.map((v, i) => cell(String(v), i)).join('  '));
}

function buildRowsForFlavor(rec, native) {
  const opNames = {
    encrypt_bench: 'encrypt',
    decrypt_bench: 'decrypt',
    fetch_bench:   'fetch',
    submit_bench:  'submit',
  };
  const rows = [];
  for (const op of Object.keys(opNames)) {
    const m = rec.results[op];
    const slowNative = (native && native[op]) ? (m.avgUs / native[op].avgUs) : NaN;
    rows.push([
      opNames[op],
      m.iterations,
      m.totalMs.toFixed(2),
      m.avgUs.toFixed(2),
      Number.isFinite(slowNative) ? ('x' + slowNative.toFixed(2)) : '—',
    ]);
  }
  return rows;
}

function summarizeFlavors(flavors, native) {
  const ops = ['encrypt_bench', 'decrypt_bench', 'fetch_bench', 'submit_bench'];
  const best = {};
  for (const op of ops) {
    let min = Infinity, who = null;
    for (const r of flavors) {
      const val = r.results[op].avgUs;
      if (val < min) { min = val; who = r; }
    }
    best[op] = { min, who };
  }

  const rows = [];
  for (const r of flavors) {
    const label = `${r.flavor.family}:${r.flavor.label} (${r.version})`;
    const enc = r.results['encrypt_bench'], dec = r.results['decrypt_bench'];
    const fch = r.results['fetch_bench'],   sub = r.results['submit_bench'];

    const sEncBest = enc.avgUs / best['encrypt_bench'].min;
    const sDecBest = dec.avgUs / best['decrypt_bench'].min;
    const sFchBest = fch.avgUs / best['fetch_bench'].min;
    const sSubBest = sub.avgUs / best['submit_bench'].min;

    const slowVsNative = (op) => (native && native[op]) ? (r.results[op].avgUs / native[op].avgUs) : NaN;

    rows.push([
      label,
      enc.avgUs.toFixed(2), dec.avgUs.toFixed(2), fch.avgUs.toFixed(2), sub.avgUs.toFixed(2),
      'x' + sEncBest.toFixed(2), 'x' + sDecBest.toFixed(2), 'x' + sFchBest.toFixed(2), 'x' + sSubBest.toFixed(2),
      Number.isFinite(slowVsNative('encrypt_bench')) ? ('x' + slowVsNative('encrypt_bench').toFixed(2)) : '—',
      Number.isFinite(slowVsNative('decrypt_bench')) ? ('x' + slowVsNative('decrypt_bench').toFixed(2)) : '—',
      Number.isFinite(slowVsNative('fetch_bench'))   ? ('x' + slowVsNative('fetch_bench').toFixed(2))   : '—',
      Number.isFinite(slowVsNative('submit_bench'))  ? ('x' + slowVsNative('submit_bench').toFixed(2))  : '—',
    ]);
  }

  return {
    rows,
    headers: [
      'flavor',
      'enc µs', 'dec µs', 'fch µs', 'sub µs',
      '×best enc', '×best dec', '×best fch', '×best sub',
      '×native enc', '×native dec', '×native fch', '×native sub',
    ],
    aligns: ['left','right','right','right','right','right','right','right','right','right','right','right','right'],
    best,
  };
}

// -------- Main --------
(async () => {
  const { iterations, browserSel, nativeSel, flavorsArg } = parseArgs(process.argv);

  // Native
  let native = null;
  if (nativeSel === 'on') {
    native = runNative(iterations);
    console.log(`\n=== Native (cargo bench) — iterations: ${iterations} ===`);
    makeTable(
      [
        ['encrypt', native.encrypt_bench.iterations, native.encrypt_bench.totalMs.toFixed(2), native.encrypt_bench.avgUs.toFixed(2), 'x1.00'],
        ['decrypt', native.decrypt_bench.iterations, native.decrypt_bench.totalMs.toFixed(2), native.decrypt_bench.avgUs.toFixed(2), 'x1.00'],
        ['fetch',   native.fetch_bench.iterations,   native.fetch_bench.totalMs.toFixed(2),   native.fetch_bench.avgUs.toFixed(2),   'x1.00'],
        ['submit',  native.submit_bench.iterations,  native.submit_bench.totalMs.toFixed(2),  native.submit_bench.avgUs.toFixed(2),  'x1.00'],
      ],
      ['op', 'iters', 'total (ms)', 'avg (µs/iter)', 'slowdown'],
      ['left','right','right','right','right']
    );
  }

  if (browserSel === 'none') {
    console.log('\n(Browsers disabled with --browser none)');
    return;
  }

  // Which families to test
  const wantChromium = (browserSel === 'chromium' || browserSel === 'all');
  const wantFirefox  = (browserSel === 'firefox'  || browserSel === 'all');

  // Which flavors to test
  const allFlavors = [];
  const requested = (flavorsArg === 'all')
    ? ['bundled','chrome','chrome-beta','chrome-dev','firefox','firefox-beta','firefox-nightly']
    : flavorsArg.split(',').map(s => s.trim()).filter(Boolean);

  if (wantChromium) {
    const chromes = ['bundled','chrome','chrome-beta','chrome-dev'];
    for (const label of chromes) if (requested.includes('all') || requested.includes(label)) {
      allFlavors.push({ family: 'chromium', label });
    }
  }
  if (wantFirefox) {
    const foxes = ['bundled','firefox','firefox-beta','firefox-nightly'];
    for (const label of foxes) if (requested.includes('all') || requested.includes(label)) {
      allFlavors.push({ family: 'firefox', label });
    }
  }

  // Serve once for all runs
  const server = await startServer(process.cwd());
  const port = server.address().port;
  const url = `http://localhost:${port}/www/index.html`;

  // Run all flavors
  const results = [];
  for (const flavor of allFlavors) {
    try {
      const rec = await runFlavor(flavor, iterations, url);
      results.push(rec);

      // Per-flavor table
      const title = `${flavor.family}:${flavor.label} (${rec.version}) — iterations: ${iterations}`;
      console.log(`\n=== ${title} ===`);
      makeTable(
        buildRowsForFlavor(rec, native),
        ['op', 'iters', 'total (ms)', 'avg (µs/iter)', 'slowdown vs native'],
        ['left','right','right','right','right']
      );
    } catch (e) {
      console.error(`\n[ERROR] Failed ${flavor.family}:${flavor.label}:`, e && e.message ? e.message : e);
    }
  }

  server.close();

  if (results.length === 0) {
    console.log('\nNo browser results.');
    return;
  }

  // Summary across flavors
  const summary = summarizeFlavors(results, native);
  console.log(`\n=== Summary: all flavors (iterations: ${iterations}) ===`);
  makeTable(summary.rows, summary.headers, summary.aligns);

  // Highlight best per op
  console.log('\nFastest per op:');
  for (const [op, { who, min }] of Object.entries(summary.best)) {
    const tag = `${who.flavor.family}:${who.flavor.label} (${who.version})`;
    const pretty = {encrypt_bench:'encrypt',decrypt_bench:'decrypt',fetch_bench:'fetch',submit_bench:'submit'}[op];
    console.log(`  ${pretty}: ${tag} — ${min.toFixed(2)} µs/iter`);
  }

})().catch(err => {
  console.error(err);
  process.exit(1);
});
