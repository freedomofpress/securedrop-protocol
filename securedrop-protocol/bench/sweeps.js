const kleur = require('kleur');

const { BenchmarkSpec } = require('./specs');
const { runSpecOnDriver, runSpecProfileIsolated } = require('./selenium');
const { prettyStatsFromUs, makeTable } = require('./reporting');

async function runBrowserSweeps(cfg, driver, baseUrl, flavor, version, coi, jSweep, kSweep, csvWriter) {
  const out = {
    fetch: {},
    decrypt: {},
  };

  // --- FETCH sweep ---
  for (const j of jSweep) {
    const spec = new BenchmarkSpec('fetch', { n: cfg.iterations, k: cfg.k, j });
    let samplesUs;

    if (cfg.mode === 'profile') {
      // Run N independent single-iteration profiles
      samplesUs = await runSpecProfileIsolated(
        flavor.family,
        version,
        baseUrl,
        new BenchmarkSpec(spec.name, { ...spec.params }),
        cfg.iterations,
      );
    } else {
      // Normal mode
      const res = await runSpecOnDriver(driver, baseUrl, new BenchmarkSpec(spec.name, { ...spec.params }));

      samplesUs = Array.isArray(res.samples_us)
        ? res.samples_us.map((x) => Math.round(x))
        : Array.isArray(res.samples_ms)
          ? res.samples_ms.map((x) => Math.round(x * 1000))
          : [];
    }

    const stats = prettyStatsFromUs(samplesUs);

    out.fetch[j] = {
      j,
      samples_us: samplesUs,
      stats,
    };

    const rows = samplesUs.map((us, i) => ({
      bench_type: 'fetch_sweep',
      family: flavor.family,
      label: flavor.label,
      browser_version: version,
      coi,
      bench: 'fetch',
      iter_index: i,
      sample_us: us,
      iterations: cfg.iterations,
      keybundles: cfg.k,
      challenges: j,
    }));
    await csvWriter.writeRecords(rows);
  }

  // --- DECRYPT sweep ---
  for (const k of kSweep) {
    const spec = new BenchmarkSpec('decrypt', { n: cfg.iterations, k });
    let samplesUs;

    if (cfg.mode === 'profile') {
      // Run N independent single-iteration profiles
      samplesUs = await runSpecProfileIsolated(
        flavor.family,
        version,
        baseUrl,
        new BenchmarkSpec(spec.name, { ...spec.params }),
        cfg.iterations,
      );
    } else {
      // Normal mode
      const res = await runSpecOnDriver(driver, baseUrl, new BenchmarkSpec(spec.name, { ...spec.params }));

      samplesUs = Array.isArray(res.samples_us)
        ? res.samples_us.map((x) => Math.round(x))
        : Array.isArray(res.samples_ms)
          ? res.samples_ms.map((x) => Math.round(x * 1000))
          : [];
    }
    const stats = prettyStatsFromUs(samplesUs);

    out.decrypt[k] = {
      k,
      samples_us: samplesUs,
      stats,
    };

    const rows = samplesUs.map((us, i) => ({
      bench_type: 'decrypt_sweep',
      family: flavor.family,
      label: flavor.label,
      browser_version: version,
      coi,
      bench: 'decrypt',
      iter_index: i,
      sample_us: us,
      iterations: cfg.iterations,
      keybundles: k,
      challenges: '',
    }));
    await csvWriter.writeRecords(rows);
  }

  // Pretty tables per flavor
  if (Object.keys(out.fetch).length) {
    const rows = [];
    for (const j of Object.keys(out.fetch).map(Number).sort((a, b) => a - b)) {
      const r = out.fetch[j];
      const s = r.stats;
      rows.push([
        j,
        s.avg_ms.toFixed(3),
        s.p50_ms.toFixed(3),
        s.p90_ms.toFixed(3),
        s.p99_ms.toFixed(3),
        s.max_ms.toFixed(3),
      ]);
    }
    console.log(`\n${kleur.bold(`=== ${flavor.family}:${flavor.label} — fetch sweep ===`)}`);
    console.log(makeTable(['j', 'avg (ms)', 'p50', 'p90', 'p99', 'max'], rows));
  }

  if (Object.keys(out.decrypt).length) {
    const rows = [];
    for (const k of Object.keys(out.decrypt).map(Number).sort((a, b) => a - b)) {
      const r = out.decrypt[k];
      const s = r.stats;
      rows.push([
        k,
        s.avg_ms.toFixed(3),
        s.p50_ms.toFixed(3),
        s.p90_ms.toFixed(3),
        s.p99_ms.toFixed(3),
        s.max_ms.toFixed(3),
      ]);
    }
    console.log(`\n${kleur.bold(`=== ${flavor.family}:${flavor.label} — decrypt sweep ===`)}`);
    console.log(makeTable(['k', 'avg (ms)', 'p50', 'p90', 'p99', 'max'], rows));
  }

  return out;
}

module.exports = {
  runBrowserSweeps,
};
