#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const { createObjectCsvWriter } = require('csv-writer');
const kleur = require('kleur');

const { parseCli } = require('./js/cli');
const { startServer } = require('./js/server');
const { BenchmarkSpec, defaultSpecs } = require('./js/specs');
const {
  expandFlavors,
  mapFlavorToVersion,
  buildDriver,
  runSpecOnDriver,
  runSpecProfileIsolated,
} = require('./js/selenium');
const { runBrowserSweeps } = require('./js/sweeps');
const { runNative, runNativeSweeps } = require('./js/native');
const { prettyStatsFromUs, makeTable } = require('./js/reporting');
const {
  rangeSweep,
  stamp,
  ensureDir,
  logInfo,
  logWarn,
  logErr,
  makeTmp,
} = require('./js/utils');

const { cfg, runFlags } = parseCli();
const {
  RUN_FETCH_SWEEP,
  RUN_DECRYPT_SWEEP,
  RUN_ANY_SWEEP,
  RUN_BASIC,
} = runFlags;

(async () => {
  const outRoot = path.join(cfg.out, stamp());
  ensureDir(outRoot);

  const csvWriter = createObjectCsvWriter({
    path: path.join(outRoot, 'all_samples.csv'),
    header: [
      { id: 'bench_type', title: 'bench_type' },
      { id: 'family', title: 'family' },
      { id: 'label', title: 'label' },
      { id: 'browser_version', title: 'browser_version' },
      { id: 'coi', title: 'coi' },
      { id: 'bench', title: 'bench' },
      { id: 'iter_index', title: 'iter_index' },
      { id: 'sample_us', title: 'sample_us' },
      { id: 'iterations', title: 'iterations' },
      { id: 'keybundles', title: 'keybundles' },
      { id: 'challenges', title: 'challenges' },
    ],
    append: false,
  });

  // Banner to confirm parameters
  logInfo(`Params locked: n=${cfg.iterations}, k=${cfg.k}, j=${cfg.j}, rng=${cfg.rng}, mode=${cfg.mode}`);

  const jSweep = (cfg.j_min != null && cfg.j_max != null && cfg.j_step != null)
    ? rangeSweep(cfg.j_min, cfg.j_max, cfg.j_step)
    : [];

  const kSweep = (cfg.k_min != null && cfg.k_max != null && cfg.k_step != null)
    ? rangeSweep(cfg.k_min, cfg.k_max, cfg.k_step)
    : [];

  // Start static server
  const { server, port } = await startServer(cfg.root);
  const baseUrl = `http://localhost:${port}/www/index.html`;
  logInfo(`Static server @ ${baseUrl}`);

  // Native (optional)
  let native = null;
  if (cfg.native === 'on' && !RUN_ANY_SWEEP) {
    logInfo('Running native...');
    try {
      native = await runNative(cfg.iterations, cfg.k, cfg.j, cfg.rng === 'on');

      if (!native || Object.keys(native).length === 0) {
        logWarn('Native bench parsed no results.');
      } else {
        const nativeBundle = {
          flavor: { family: 'native', label: 'native' },
          version: 'N/A',
          coi: true,
          benches: native,
        };

        const nativeJsonPath = path.join(outRoot, 'native.json');
        fs.writeFileSync(nativeJsonPath, JSON.stringify(nativeBundle, null, 2));
        logInfo(`Saved ${nativeJsonPath}`);

        const nativeRows = [];

        for (const bench of Object.keys(native)) {
          const rec = native[bench];
          const samples = rec.samples_us || [];

          samples.forEach((us, i) => {
            nativeRows.push({
              bench_type: 'basic',
              family: 'native',
              label: 'native',
              browser_version: 'N/A',
              coi: true,
              bench,
              iter_index: i,
              sample_us: us,
              iterations: rec.iterations ?? '',
              keybundles: rec.keybundles ?? '',
              challenges: rec.challenges ?? '',
            });
          });
        }

        await csvWriter.writeRecords(nativeRows);

        const prettyTable = [];
        for (const op of ['encrypt', 'decrypt', 'fetch']) {
          const rec = native?.[op];
          if (!rec) continue;

          const s = prettyStatsFromUs(rec.samples_us || []);

          prettyTable.push([
            op,
            rec.iterations ?? cfg.iterations,
            s.avg_ms.toFixed(3),
            s.p50_ms.toFixed(3),
            s.p90_ms.toFixed(3),
            s.p99_ms.toFixed(3),
            s.max_ms.toFixed(3),
          ]);
        }

        if (prettyTable.length) {
          console.log(`\n${makeTable(
            ['op', 'iters', 'avg (ms)', 'p50', 'p90', 'p99', 'max'],
            prettyTable,
          )}`);
        }
      }
    } catch (e) {
      logWarn('Native bench failed:', e.message);
    }
  }

  let nativeSweeps = null;
  if (RUN_ANY_SWEEP) {
    logInfo('Running native sweeps...');

    nativeSweeps = await runNativeSweeps(
      cfg,
      cfg.iterations,
      RUN_FETCH_SWEEP ? jSweep : [],
      RUN_DECRYPT_SWEEP ? kSweep : [],
      csvWriter,
    );

    const outFile = path.join(outRoot, 'native_sweeps.json');
    fs.writeFileSync(outFile, JSON.stringify(nativeSweeps, null, 2));
    logInfo(`Saved ${outFile}`);
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

  // store a traditional summary for per-flavor tables, and build a pivot for the final table
  const pivot = new Map(); // flavorKey -> { encrypt: "1.234 (x2.00)", decrypt: "...", fetch: "..." }

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
        if (!RUN_ANY_SWEEP) {
          let samplesUs = [];
          let benchName = spec.name;
          let iterations = cfg.iterations;
          let keybundles = spec.params.k ?? null;
          let challenges = spec.params.j ?? null;

          if (cfg.mode === 'profile') {
            samplesUs = await runSpecProfileIsolated(
              flavor.family,
              versionLabel,
              baseUrl,
              spec,
              cfg.iterations,
            );
          } else {
            const specWithMode = new BenchmarkSpec(spec.name, { ...spec.params });
            const res = await runSpecOnDriver(driver, baseUrl, specWithMode);

            samplesUs = Array.isArray(res.samples_us)
              ? res.samples_us.map((x) => Math.round(x))
              : Array.isArray(res.samples_ms)
                ? res.samples_ms.map((x) => Math.round(x * 1000))
                : [];
          }

          const norm = {
            bench: benchName,
            iterations,
            keybundles,
            challenges,
            samples_us: samplesUs,
          };

          flavorBundle.benches[spec.name] = norm;

          const rows = samplesUs.map((us, i) => ({
            bench_type: 'basic',
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

          // ---- summary + pivot for BASIC benches only ----
          const s = prettyStatsFromUs(samplesUs);
          const nativeRec = native?.[norm.bench];
          const nativeAvgUs = nativeRec?.avg_us
            ?? (nativeRec?.samples_us
              ? (nativeRec.samples_us.reduce((a, b) => a + b, 0) / (nativeRec.samples_us.length || 1))
              : null);
          const slowdown = (nativeAvgUs && nativeAvgUs > 0)
            ? (s.avg_ms * 1000) / nativeAvgUs
            : null;

          const cell = slowdown != null
            ? `${s.avg_ms.toFixed(3)} (x${slowdown.toFixed(2)})`
            : `${s.avg_ms.toFixed(3)}`;

          if (!pivot.has(flavorKey)) pivot.set(flavorKey, {});
          pivot.get(flavorKey)[norm.bench] = cell;
        }
      }

      // Write per-flavor JSON artifact
      fs.writeFileSync(jsonOutFile, JSON.stringify(flavorBundle, null, 2));

      // SWEEP MODE (fetch-sweep-only, decrypt-sweep-only, sweeps-only)
      if (RUN_ANY_SWEEP) {
        logInfo(`Running sweeps for ${flavor.family}:${flavor.label} ...`);

        const sweepOut = await runBrowserSweeps(
          cfg,
          driver,
          baseUrl,
          flavor,
          version,
          coi,
          RUN_FETCH_SWEEP ? jSweep : [],
          RUN_DECRYPT_SWEEP ? kSweep : [],
          csvWriter,
        );

        const sweepFile = path.join(outRoot, `${flavor.family}-${flavor.label}-sweeps.json`);
        fs.writeFileSync(sweepFile, JSON.stringify(sweepOut, null, 2));
        logInfo(`Saved ${sweepFile}`);
      }
      // Per-flavor table (unchanged, detailed stats + ×native)
      if (RUN_BASIC) {
        console.log(`\n${kleur.bold(`=== ${flavor.family}:${flavor.label} (${version}) — iterations: ${cfg.iterations} ===`)}`);
        const fRows = Object.values(flavorBundle.benches).map((b) => {
          const s = prettyStatsFromUs(b.samples_us);
          const nativeRec = native?.[b.bench];
          const nativeAvgUs = nativeRec?.avg_us
            ?? (nativeRec?.samples_us
              ? (nativeRec.samples_us.reduce((a, c) => a + c, 0) / (nativeRec.samples_us.length || 1))
              : null);
          const slowdown = (nativeAvgUs && nativeAvgUs > 0) ? (s.avg_ms * 1000) / nativeAvgUs : null;
          return [
            b.bench,
            b.iterations,
            s.avg_ms.toFixed(3),
            s.p50_ms.toFixed(3),
            s.p90_ms.toFixed(3),
            s.p99_ms.toFixed(3),
            s.max_ms.toFixed(3),
            slowdown != null ? `x${slowdown.toFixed(2)}` : '—',
          ];
        });
        console.log(makeTable(
          ['op', 'iters', 'avg (ms)', 'p50', 'p90', 'p99', 'max', '×native'],
          fRows,
        ));
      }
    } catch (e) {
      logErr(`Failed ${flavor.family}:${flavor.label}: ${e.message}`);
    } finally {
      if (driver) await driver.quit();
      try {
        fs.rmSync(tmpProfile, { recursive: true, force: true });
      } catch {
        // ignore cleanup failures
      }
    }
  }

  // Global summary (PIVOT: one row per browser, columns are ops with "avg (xSlowdown)")
  if (pivot.size) {
    const headers = ['browser', 'encrypt', 'decrypt', 'fetch'];
    const rows = [];
    for (const [flavorKey, cells] of pivot.entries()) {
      rows.push([
        flavorKey,
        cells.encrypt || '—',
        cells.decrypt || '—',
        cells.fetch || '—',
      ]);
    }
    console.log(`\n${kleur.bold(`=== Summary by browser (iterations: ${cfg.iterations}) ===`)}`);
    console.log(makeTable(headers, rows));
  } else {
    logWarn('No browser results.');
  }

  server.close();
  logInfo(`Artifacts written to ${outRoot}`);
})().catch((err) => {
  logErr(err.stack || err);
  process.exit(1);
});
