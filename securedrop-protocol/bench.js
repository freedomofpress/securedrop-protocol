#!/usr/bin/env node

const path = require('path');
const fs = require('fs');
const os = require('os');

const express = require('express');
const serveStatic = require('serve-static');

const { execa } = require('execa');
const yargs = require('yargs');
const { hideBin } = require('yargs/helpers');
const { z } = require('zod');
const ss = require('simple-statistics');
const { createObjectCsvWriter } = require('csv-writer');
const kleur = require('kleur');

const { Builder, Capabilities } = require('selenium-webdriver');
const chrome  = require('selenium-webdriver/chrome');
const firefox = require('selenium-webdriver/firefox');

// ------------------------------ CLI ------------------------------

const CliSchema = z.object({
  iterations: z.number().int().positive().default(100),
  browser: z.enum(['chromium','firefox','all','none']).default('all'),
  native: z.enum(['on','off']).default('on'),
  flavors: z.string().default('all'),
  mode: z.enum(['warm','profile','worker']).default('warm'),
  k: z.number().int().nonnegative().default(500),
  j: z.number().int().nonnegative().default(3000),
  rng: z.enum(['on','off']).default('off'),
  out: z.string().default('out'),
  root: z.string().default(process.cwd()),
});

const argv = yargs(hideBin(process.argv))
  .option('iterations', { alias: 'n', type: 'number', describe: 'Iterations per bench' })
  .option('browser',    { type: 'string', describe: 'chromium|firefox|all|none' })
  .option('native',     { type: 'string', describe: 'on|off' })
  .option('flavors',    { type: 'string', describe: 'all or comma list (chrome,chrome-beta,chrome-dev,firefox,firefox-beta,firefox-nightly,bundled)' })
  .option('mode',       { type: 'string', describe: 'warm|profile|worker' })
  .option('k',          { type: 'number', describe: 'Keybundles per journalist' })
  .option('j',          { type: 'number', describe: 'Challenges per iter (fetch)' })
  .option('rng',        { type: 'string', describe: 'Include RNG time inside encrypt loop (on|off)' })
  .option('out',        { type: 'string', describe: 'Output directory root' })
  .option('root',       { type: 'string', describe: 'Static server root (contains /www/index.html)' })
  .strict()
  .help()
  .parse();

const cfg = CliSchema.parse({
  iterations: argv.iterations,
  browser: argv.browser,
  native: argv.native,
  flavors: argv.flavors,
  mode: argv.mode,
  k: argv.k,
  j: argv.j,
  rng: argv.rng,
  out: argv.out,
  root: argv.root,
});

// ------------------------------ Utils ------------------------------

const stamp = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2,'0');
  return `${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
};
const ensureDir = (p) => fs.mkdirSync(p, { recursive: true });

function logInfo(...a){ console.log(kleur.cyan('[i]'), ...a); }
function logWarn(...a){ console.warn(kleur.yellow('[!]'), ...a); }
function logErr (...a){ console.error(kleur.red('[x]'), ...a); }

// ------------------------------ Static server (COOP/COEP) ------------------------------

async function startServer(rootDir) {
  const app = express();

  // COOP/COEP for crossOriginIsolated + precise timers + SAB
  app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Timing-Allow-Origin', '*');
    next();
  });

  app.use(serveStatic(rootDir, {
    fallthrough: true,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.wasm')) {
        res.setHeader('Content-Type', 'application/wasm');
      }
    }
  }));

  // 404
  app.use((req, res) => res.status(404).send('Not found'));

  return new Promise((resolve) => {
    const srv = app.listen(0, () => {
      const { port } = srv.address();
      resolve({ server: srv, port });
    });
  });
}

// ------------------------------ Benchmark spec ------------------------------

class BenchmarkSpec {
  /**
   * @param {string} name 'encrypt' | 'decrypt_journalist' | 'decrypt_source' | 'fetch'
   * @param {object} params { n, k, j, include_rng }
   */
  constructor(name, params) {
    this.name = name;
    this.params = { ...params };
  }
  toQuery() {
    const u = new URLSearchParams();
    u.set('bench', this.name);
    if (this.params.n != null) u.set('n', String(this.params.n));
    if (this.params.k != null) u.set('k', String(this.params.k));
    if (this.params.j != null) u.set('j', String(this.params.j));
    if (this.params.include_rng) u.set('include_rng', '1');
    u.set('raw', 'json');   // page emits JSON & window.benchResults*
    u.set('quiet', '1');    // no pretty printing
    return '?' + u.toString();
  }
}

function defaultSpecs(iterations, k, j, rngOn) {
  return [
    new BenchmarkSpec('encrypt',            { n: iterations, k, include_rng: rngOn }),
    new BenchmarkSpec('decrypt_journalist', { n: iterations, k }),
    new BenchmarkSpec('decrypt_source',     { n: iterations, k: 1 }),
    new BenchmarkSpec('fetch',              { n: iterations, k, j }),
  ];
}

// ------------------------------ Selenium flavors ------------------------------

function expandFlavors(browserSel, flavorsArg) {
  const wantChromium = browserSel === 'chromium' || browserSel === 'all';
  const wantFirefox  = browserSel === 'firefox'  || browserSel === 'all';

  const requested = (flavorsArg === 'all')
    ? ['bundled','chrome','chrome-beta','chrome-dev','firefox','firefox-beta','firefox-nightly']
    : flavorsArg.split(',').map(s => s.trim()).filter(Boolean);

  const out = [];
  if (wantChromium) {
    ['bundled','chrome','chrome-beta','chrome-dev'].forEach(label => {
      if (requested.includes('all') || requested.includes(label)) out.push({ family:'chromium', label });
    });
  }
  if (wantFirefox) {
    ['bundled','firefox','firefox-beta','firefox-nightly'].forEach(label => {
      if (requested.includes('all') || requested.includes(label)) out.push({ family:'firefox', label });
    });
  }
  return out;
}

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
    const opts = new chrome.Options()
      .addArguments(
        '--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check',
        '--disable-extensions', `--user-data-dir=${profileDir}`,
        '--remote-debugging-port=0','--no-sandbox','--disable-dev-shm-usage',
        '--enable-features=WebAssemblySimd'
      );
    let caps = new Capabilities().setBrowserName('chrome');
    if (versionLabel) caps = caps.set('browserVersion', versionLabel);
    return await new Builder().withCapabilities(caps).setChromeOptions(opts).build();
  }

  const opts = new firefox.Options();
  opts.addArguments('-headless');
  opts.setProfile(profileDir);
  opts.setPreference('javascript.options.wasm', true);
  opts.setPreference('javascript.options.wasm_simd', true);
  opts.setPreference('javascript.options.wasm_relaxed_simd', true);
  opts.setPreference('javascript.options.wasm_threads', true);

  let caps = new Capabilities().setBrowserName('firefox');
  if (versionLabel) caps = caps.set('browserVersion', versionLabel);
  return await new Builder().withCapabilities(caps).setFirefoxOptions(opts).build();
}

function makeTmp(prefix){ return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

//
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
        ? res.samples_us.map(x => Math.round(x))
        : Array.isArray(res.samples_ms)
          ? res.samples_ms.map(x => Math.round(x * 1000))
          : [];

      if (samplesUs.length !== 1) {
        // throw an error?
      } else {
        combined.push(samplesUs[0]);
      }
    } finally {
      if (driver) await driver.quit();
      try { fs.rmSync(tmpProfile, { recursive: true, force: true }); } catch {}
    }
  }
  return combined;
}


// ------------------------------ Page runner (via window.* API) ------------------------------

async function runSpecOnDriver(driver, baseUrl, spec, timeoutMs = 60_000) {
  const url = baseUrl + spec.toQuery();
  await driver.get(url);

  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const ready = await driver.executeScript('return !!window.benchReady;');
    if (ready) {
      const obj = await driver.executeScript('return window.benchResultsByName && window.benchResultsByName[arguments[0]];', spec.name);
      if (obj) return obj; // contains samples_us (or samples_ms fallback)
    }
    await driver.sleep(100);
  }
  throw new Error(`Timeout waiting for payload (bench=${spec.name})`);
}

// ------------------------------ Native (JSON, µs) ------------------------------

function statsFromUs(samplesUs) {
  const s = samplesUs.slice().sort((a,b)=>a-b);
  const pick = (q) => s.length ? s[Math.min(s.length-1, Math.round(q * (s.length - 1)))] : 0;
  const sum = s.reduce((a,b)=>a+b, 0);
  const avg = s.length ? sum / s.length : 0;
  return {
    n: s.length,
    total_us: sum,
    avg_us: avg,
    min_us: s[0] ?? 0,
    p50_us: pick(0.50),
    p90_us: pick(0.90),
    p99_us: pick(0.99),
    max_us: s[s.length-1] ?? 0,
  };
}

async function runNative(iterations, k, j, rngOn) {
  // Lock params for native; pass exactly what web harness gets.
  const plans = [
    { bench: 'encrypt',            args: ['encrypt', '-n', String(iterations), '-k', String(k), ...(rngOn ? ['--include-rng'] : [])],
      expect: { iterations, keybundles: k, challenges: null } },
    { bench: 'decrypt_journalist', args: ['decrypt', '-n', String(iterations), '-k', String(k)],
      expect: { iterations, keybundles: k, challenges: null } },
    { bench: 'decrypt_source',     args: ['decrypt', '-n', String(iterations), '-k', '1'],
      expect: { iterations, keybundles: 1, challenges: null } },
    { bench: 'fetch',              args: ['fetch', '-n', String(iterations), '-k', String(k), '-j', String(j)],
      expect: { iterations, keybundles: k, challenges: j } },
  ];

  const results = {};
  for (const p of plans) {
    try {
      const { stdout } = await execa(
        'cargo',
        ['bench','--bench','manual','--', ...p.args, '--raw','json','--quiet'],
        { stdio: 'pipe' }
      );
      const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
      const jsonLine = lines.reverse().find(l => l.startsWith('{') && l.endsWith('}'));
      if (!jsonLine) { logWarn(`Native: no JSON for ${p.bench}`); continue; }
      const obj = JSON.parse(jsonLine);

      // Normalize to µs
      let samplesUs = [];
      if (Array.isArray(obj.samples_us)) {
        samplesUs = obj.samples_us.map(x => Math.round(x));
      } else if (Array.isArray(obj.samples_ms)) {
        samplesUs = obj.samples_ms.map(x => Math.round(x * 1000));
      } else {
        logWarn(`Native: no samples array for ${p.bench}`);
        continue;
      }
      const stats = statsFromUs(samplesUs);

      const rec = {
        bench: p.bench,
        iterations: obj.iterations ?? p.expect.iterations,
        keybundles: obj.keybundles ?? p.expect.keybundles,
        challenges: obj.challenges ?? p.expect.challenges,
        samples_us: samplesUs,
        ...stats,
      };

      results[p.bench] = rec;
    } catch (e) {
      logWarn(`Native bench failed ${p.bench}: ${e.message}`);
    }
  }
  return results;
}

// ------------------------------ Reporting helpers ------------------------------

function prettyStatsFromUs(samplesUs) {
  const ms = samplesUs.map(us => us / 1000);
  const s = ms.slice().sort((a,b)=>a-b);
  return {
    n: s.length,
    total_ms: ss.sum(s),
    avg_ms: ss.mean(s),
    min_ms: s[0] ?? 0,
    p50_ms: ss.quantileSorted(s, 0.5),
    p90_ms: ss.quantileSorted(s, 0.9),
    p99_ms: ss.quantileSorted(s, 0.99),
    max_ms: s[s.length-1] ?? 0,
  };
}

function makeTable(headers, rows) {
  const Table = require('cli-table3');
  const t = new Table({ head: headers });
  rows.forEach(r => t.push(r));
  return t.toString();
}

// ------------------------------ Main ------------------------------

(async () => {
  const outRoot = path.join(cfg.out, stamp());
  ensureDir(outRoot);

  // Banner to confirm parameters
  logInfo(`Params locked: n=${cfg.iterations}, k=${cfg.k}, j=${cfg.j}, rng=${cfg.rng}, mode=${cfg.mode}`);

  // Start static server
  const { server, port } = await startServer(cfg.root);
  const baseUrl = `http://localhost:${port}/www/index.html`;
  logInfo(`Static server @ ${baseUrl}`);

  // Native (optional)
  let native = null;
  if (cfg.native === 'on') {
    logInfo('Running native (cargo bench, JSON)...');
    try {
      native = await runNative(cfg.iterations, cfg.k, cfg.j, cfg.rng === 'on');

      const nativeRows = [];
      for (const op of ['encrypt','decrypt_journalist','decrypt_source','fetch']) {
        const rec = native?.[op];
        if (rec) {
          const s = prettyStatsFromUs(rec.samples_us || []);
          nativeRows.push([
            op,
            rec.iterations ?? cfg.iterations,
            (op === 'decrypt_journalist' ? (rec.keybundles ?? '—') : '—'),
            (rec.challenges ?? '—'),
            s.avg_ms.toFixed(3),
            s.p50_ms.toFixed(3),
            s.p90_ms.toFixed(3),
            s.p99_ms.toFixed(3),
            s.max_ms.toFixed(3),
          ]);
        }
      }

      if (nativeRows.length) {
        console.log('\n' + makeTable(
          ['op','iters','k','j','avg (ms)','p50','p90','p99','max'],
          nativeRows
        ));
      } else {
        logWarn('Native bench parsed no results.');
      }
    } catch (e) {
      logWarn('Native bench failed:', e.message);
    }
  }

  if (cfg.browser === 'none') {
    logWarn('Browsers disabled (--browser none). Done.');
    server.close();
    return;
  }

  const specs = defaultSpecs(cfg.iterations, cfg.k, cfg.j, cfg.rng === 'on');
  const flavors = expandFlavors(cfg.browser, cfg.flavors);

  if (flavors.length === 0) {
    logWarn('No flavors selected.');
    server.close();
    return;
  }

  // CSV writer for per-iteration tidy data (store µs)
  const csvWriter = createObjectCsvWriter({
    path: path.join(outRoot, 'all_samples.csv'),
    header: [
      { id: 'family', title: 'family' },
      { id: 'label',  title: 'label' },
      { id: 'browser_version', title: 'browser_version' },
      { id: 'coi',    title: 'coi' },
      { id: 'bench',  title: 'bench' },
      { id: 'iter_index', title: 'iter_index' },
      { id: 'sample_us',  title: 'sample_us' },    // microseconds
      { id: 'iterations', title: 'iterations' },
      { id: 'keybundles', title: 'keybundles' },
      { id: 'challenges', title: 'challenges' },
    ],
    append: false,
  });

  // store a traditional summary for per-flavor tables, and build a pivot for the final table
  const pivot = new Map(); // flavorKey -> { encrypt: "1.234 (x2.00)", decrypt_journalist: "...", decrypt_source: "...", fetch: "..." }

  for (const flavor of flavors) {
    const versionLabel = mapFlavorToVersion(flavor.family, flavor.label);
    const tmpProfile = makeTmp(`bench-${flavor.family}-${flavor.label}-`);
    const jsonOutFile = path.join(outRoot, `${flavor.family}-${flavor.label}.json`);

    let driver;
    try {
      driver = await buildDriver(flavor.family, versionLabel, tmpProfile);
      await driver.get(baseUrl); // initial load to evaluate capabilities

      const caps = await driver.getCapabilities();
      const version = caps.get('browserVersion') || 'unknown';
      const coi = await driver.executeScript('return !!globalThis.crossOriginIsolated;');
      if (!coi) logWarn(`${flavor.family}:${flavor.label} crossOriginIsolated=false; timers may be coarse.`);

      const flavorBundle = { flavor, version, coi, benches: {} };
      const flavorKey = `${flavor.family}:${flavor.label} (${version})`;

       for (const spec of specs) {
        // Modes:
        //  - warm: single page, N iterations (current behavior)
        //  - profile: N runs, 1 iteration each, fresh profile/driver (strong isolation)
        //  - worker: single page, N iterations, Worker-per-iter (page must implement)

        // Defaults based on the spec (used in all modes)
        let samplesUs = [];
        let benchName   = spec.name;
        let iterations  = cfg.iterations;
        let keybundles  = (spec.name === 'decrypt_journalist') ? cfg.k : null;
        let challenges  = (spec.name === 'fetch') ? cfg.j : null;

        if (cfg.mode === 'profile') {
          // Strong isolation: 1 iter per fresh profile/driver
          samplesUs = await runSpecProfileIsolated(flavor.family, versionLabel, baseUrl, spec, cfg.iterations);
        } else {
          // warm/worker: page runs the loop; for worker we pass a hint via query
          const specWithMode = new BenchmarkSpec(
            spec.name,
            { ...spec.params, ...(cfg.mode === 'worker' ? { isolation: 'worker' } : {}) }
          );
          const res = await runSpecOnDriver(driver, baseUrl, specWithMode);
          samplesUs = Array.isArray(res.samples_us)
            ? res.samples_us.map(x => Math.round(x))
            : Array.isArray(res.samples_ms)
              ? res.samples_ms.map(x => Math.round(x * 1000))
              : [];
          // If the page returned metadata, let it override our defaults
          if (res) {
            benchName  = res.bench || benchName;
            iterations = (res.iterations ?? iterations);
            if (spec.name === 'decrypt_journalist') keybundles = (res.keybundles ?? keybundles);
            if (spec.name === 'fetch')             challenges = (res.challenges ?? challenges);
          }
        }

        // Build normalized record
        const norm = {
          bench: benchName,
          iterations,
          keybundles,
          challenges,
          samples_us: samplesUs,
        };

        flavorBundle.benches[spec.name] = norm;

        // emit tidy CSV rows
        const rows = samplesUs.map((us, i) => ({
          family: flavor.family,
          label: flavor.label,
          browser_version: version,
          coi,
          bench: norm.bench,
          iter_index: i,
          sample_us: us,
          iterations: norm.iterations,
          keybundles: norm.keybundles ?? '',
          challenges: norm.challenges ?? '',
        }));
        await csvWriter.writeRecords(rows);

        // summary (ms) + ×native (for per-flavor table + pivot cell)
        const s = prettyStatsFromUs(samplesUs);
        const nativeRec = native?.[norm.bench];
        const nativeAvgUs = nativeRec?.avg_us ?? (nativeRec?.samples_us ? (nativeRec.samples_us.reduce((a,b)=>a+b,0)/(nativeRec.samples_us.length||1)) : null);
        const slowdown = (nativeAvgUs && nativeAvgUs > 0) ? (s.avg_ms * 1000) / nativeAvgUs : null;

        // populate pivot cell text: "<avg> (x<slowdown>)"
        const cell = slowdown != null
          ? `${s.avg_ms.toFixed(3)} (x${slowdown.toFixed(2)})`
          : `${s.avg_ms.toFixed(3)}`;

        if (!pivot.has(flavorKey)) pivot.set(flavorKey, {});
        pivot.get(flavorKey)[norm.bench] = cell;
      }

      // Write per-flavor JSON artifact
      fs.writeFileSync(jsonOutFile, JSON.stringify(flavorBundle, null, 2));

      // Per-flavor table (unchanged, detailed stats + ×native)
      console.log('\n' + kleur.bold(`=== ${flavor.family}:${flavor.label} (${version}) — iterations: ${cfg.iterations} ===`));
      const fRows = Object.values(flavorBundle.benches).map(b => {
        const s = prettyStatsFromUs(b.samples_us);
        const nativeRec = native?.[b.bench];
        const nativeAvgUs = nativeRec?.avg_us ?? (nativeRec?.samples_us ? (nativeRec.samples_us.reduce((a,c)=>a+c,0)/(nativeRec.samples_us.length||1)) : null);
        const slowdown = (nativeAvgUs && nativeAvgUs > 0) ? (s.avg_ms * 1000) / nativeAvgUs : null;
        return [
          b.bench,
          b.iterations,
          (b.keybundles ?? '—'),
          (b.challenges ?? '—'),
          s.avg_ms.toFixed(3),
          s.p50_ms.toFixed(3),
          s.p90_ms.toFixed(3),
          s.p99_ms.toFixed(3),
          s.max_ms.toFixed(3),
          slowdown != null ? `x${slowdown.toFixed(2)}` : '—',
        ];
      });
      console.log(makeTable(
        ['op','iters','k','j','avg (ms)','p50','p90','p99','max','×native'],
        fRows
      ));

    } catch (e) {
      logErr(`Failed ${flavor.family}:${flavor.label}: ${e.message}`);
    } finally {
      if (driver) await driver.quit();
      try { fs.rmSync(tmpProfile, { recursive: true, force: true }); } catch {}
    }
  }

  // Global summary (PIVOT: one row per browser, columns are ops with "avg (xSlowdown)")
  if (pivot.size) {
    const headers = ['browser','encrypt','decrypt_journalist','decrypt_source','fetch'];
    const rows = [];
    for (const [flavorKey, cells] of pivot.entries()) {
      rows.push([
        flavorKey,
        cells.encrypt || '—',
        cells.decrypt_journalist || '—',
        cells.decrypt_source || '—',
        cells.fetch || '—',
      ]);
    }
    console.log('\n' + kleur.bold(`=== Summary by browser (iterations: ${cfg.iterations}) ===`));
    console.log(makeTable(headers, rows));
  } else {
    logWarn('No browser results.');
  }

  server.close();
  logInfo(`Artifacts written to ${outRoot}`);
})().catch(err => {
  logErr(err.stack || err);
  process.exit(1);
});
