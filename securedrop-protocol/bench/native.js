const { execa } = require('execa');
const kleur = require('kleur');

const { logWarn } = require('./utils');
const { prettyStatsFromUs, makeTable } = require('./reporting');

function statsFromUs(samplesUs) {
  const s = samplesUs.slice().sort((a, b) => a - b);
  const pick = (q) => (s.length ? s[Math.min(s.length - 1, Math.round(q * (s.length - 1)))] : 0);
  const sum = s.reduce((a, b) => a + b, 0);
  const avg = s.length ? sum / s.length : 0;
  return {
    n: s.length,
    total_us: sum,
    avg_us: avg,
    min_us: s[0] ?? 0,
    p50_us: pick(0.50),
    p90_us: pick(0.90),
    p99_us: pick(0.99),
    max_us: s[s.length - 1] ?? 0,
  };
}

async function runNativeSweeps(cfg, baseIterations, jSweep, kSweep, csvWriter) {
  const results = {
    fetch: {},
    decrypt_journalist: {},
  };

  // --- FETCH sweep (vary j) ---
  for (const j of jSweep) {
    const args = ['fetch', '-n', String(baseIterations), '-k', '500', '-j', String(j), '--raw', 'json', '--quiet'];

    let samplesUs = [];

    if (cfg.mode === 'profile') {
      // One single native iteration per profile
      for (let i = 0; i < cfg.iterations; i++) {
        const { stdout } = await execa('cargo', [
          'bench',
          '--bench',
          'manual',
          '--',
          ...args,
          '--raw',
          'json',
          '--quiet',
        ]);

        const jsonLine = stdout
          .trim()
          .split(/\r?\n/)
          .filter(Boolean)
          .reverse()
          .find((l) => l.startsWith('{') && l.endsWith('}'));

        if (!jsonLine) continue;
        const obj = JSON.parse(jsonLine);

        const us = Array.isArray(obj.samples_us)
          ? Math.round(obj.samples_us[0])
          : Array.isArray(obj.samples_ms)
            ? Math.round(obj.samples_ms[0] * 1000)
            : null;

        if (us != null) samplesUs.push(us);
      }
    } else {
      // warm mode = existing aggregated native benchmark
      const { stdout } = await execa('cargo', [
        'bench',
        '--bench',
        'manual',
        '--',
        ...args,
        '--raw',
        'json',
        '--quiet',
      ]);

      const jsonLine = stdout
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .reverse()
        .find((l) => l.startsWith('{') && l.endsWith('}'));

      if (jsonLine) {
        const obj = JSON.parse(jsonLine);
        samplesUs = Array.isArray(obj.samples_us)
          ? obj.samples_us.map((x) => Math.round(x))
          : Array.isArray(obj.samples_ms)
            ? obj.samples_ms.map((x) => Math.round(x * 1000))
            : [];
      }
    }

    const stats = statsFromUs(samplesUs);

    results.fetch[j] = {
      j,
      iterations: baseIterations, // cfg.iterations
      keybundles: 500, // native fetch always uses -k 500
      samples_us: samplesUs,
      stats,
    };

    // CSV rows
    const rows = samplesUs.map((us, i) => ({
      bench_type: 'fetch_sweep',
      family: 'native',
      label: 'native',
      browser_version: 'N/A',
      coi: true,
      bench: 'fetch',
      iter_index: i,
      sample_us: us,
      iterations: baseIterations,
      keybundles: 500,
      challenges: j,
    }));
    await csvWriter.writeRecords(rows);
  }

  // --- DECRYPT JOURNALIST sweep (vary k) ---
  for (const k of kSweep) {
    const args = ['decrypt', '-n', String(baseIterations), '-k', String(k), '--raw', 'json', '--quiet'];

    let samplesUs = [];

    if (cfg.mode === 'profile') {
      // One single native iteration per profile
      for (let i = 0; i < cfg.iterations; i++) {
        const { stdout } = await execa('cargo', [
          'bench',
          '--bench',
          'manual',
          '--',
          ...args,
          '--raw',
          'json',
          '--quiet',
        ]);

        const jsonLine = stdout
          .trim()
          .split(/\r?\n/)
          .filter(Boolean)
          .reverse()
          .find((l) => l.startsWith('{') && l.endsWith('}'));

        if (!jsonLine) continue;
        const obj = JSON.parse(jsonLine);

        const us = Array.isArray(obj.samples_us)
          ? Math.round(obj.samples_us[0])
          : Array.isArray(obj.samples_ms)
            ? Math.round(obj.samples_ms[0] * 1000)
            : null;

        if (us != null) samplesUs.push(us);
      }
    } else {
      // warm mode = existing aggregated native benchmark
      const { stdout } = await execa('cargo', [
        'bench',
        '--bench',
        'manual',
        '--',
        ...args,
        '--raw',
        'json',
        '--quiet',
      ]);

      const jsonLine = stdout
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .reverse()
        .find((l) => l.startsWith('{') && l.endsWith('}'));

      if (jsonLine) {
        const obj = JSON.parse(jsonLine);
        samplesUs = Array.isArray(obj.samples_us)
          ? obj.samples_us.map((x) => Math.round(x))
          : Array.isArray(obj.samples_ms)
            ? obj.samples_ms.map((x) => Math.round(x * 1000))
            : [];
      }
    }

    const stats = statsFromUs(samplesUs);

    results.decrypt_journalist[k] = {
      k,
      iterations: baseIterations,
      samples_us: samplesUs,
      stats,
    };

    const rows = samplesUs.map((us, i) => ({
      bench_type: 'decryptj_sweep',
      family: 'native',
      label: 'native',
      browser_version: 'N/A',
      coi: true,
      bench: 'decrypt_journalist',
      iter_index: i,
      sample_us: us,
      iterations: baseIterations,
      keybundles: k,
      challenges: '',
    }));
    await csvWriter.writeRecords(rows);
  }

  // Pretty tables
  if (Object.keys(results.fetch).length) {
    const rows = [];
    for (const j of Object.keys(results.fetch).map(Number).sort((a, b) => a - b)) {
      const r = results.fetch[j];
      const s = prettyStatsFromUs(r.samples_us);
      rows.push([
        j,
        r.iterations,
        r.keybundles ?? '—',
        s.avg_ms.toFixed(3),
        s.p50_ms.toFixed(3),
        s.p90_ms.toFixed(3),
        s.p99_ms.toFixed(3),
        s.max_ms.toFixed(3),
      ]);
    }
    console.log(`\n${kleur.bold('=== Native fetch sweep ===')}`);
    console.log(makeTable(['j', 'iters', 'k', 'avg (ms)', 'p50', 'p90', 'p99', 'max'], rows));
  }

  if (Object.keys(results.decrypt_journalist).length) {
    const rows = [];
    for (const k of Object.keys(results.decrypt_journalist).map(Number).sort((a, b) => a - b)) {
      const r = results.decrypt_journalist[k];
      const s = prettyStatsFromUs(r.samples_us);
      rows.push([
        k,
        r.iterations,
        s.avg_ms.toFixed(3),
        s.p50_ms.toFixed(3),
        s.p90_ms.toFixed(3),
        s.p99_ms.toFixed(3),
        s.max_ms.toFixed(3),
      ]);
    }
    console.log(`\n${kleur.bold('=== Native decrypt_journalist sweep ===')}`);
    console.log(makeTable(['k', 'iters', 'avg (ms)', 'p50', 'p90', 'p99', 'max'], rows));
  }

  return results;
}

async function runNative(iterations, k, j, rngOn) {
  const plans = [
    {
      bench: 'encrypt',
      args: ['encrypt', '-n', String(iterations), '-k', String(k), ...(rngOn ? ['--include-rng'] : [])],
      expect: { iterations, keybundles: k, challenges: null },
    },
    {
      bench: 'decrypt_journalist',
      args: ['decrypt', '-n', String(iterations), '-k', String(k)],
      expect: { iterations, keybundles: k, challenges: null },
    },
    {
      bench: 'decrypt_source',
      args: ['decrypt', '-n', String(iterations), '-k', '1'],
      expect: { iterations, keybundles: 1, challenges: null },
    },
    {
      bench: 'fetch',
      args: ['fetch', '-n', String(iterations), '-k', String(k), '-j', String(j)],
      expect: { iterations, keybundles: k, challenges: j },
    },
  ];

  const results = {};
  for (const p of plans) {
    try {
      const { stdout } = await execa(
        'cargo',
        ['bench', '--bench', 'manual', '--', ...p.args, '--raw', 'json', '--quiet'],
        { stdio: 'pipe' },
      );
      const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
      const jsonLine = lines.reverse().find((l) => l.startsWith('{') && l.endsWith('}'));
      if (!jsonLine) {
        logWarn(`Native: no JSON for ${p.bench}`);
        continue;
      }
      const obj = JSON.parse(jsonLine);

      // Normalize to µs
      let samplesUs = [];
      if (Array.isArray(obj.samples_us)) {
        samplesUs = obj.samples_us.map((x) => Math.round(x));
      } else if (Array.isArray(obj.samples_ms)) {
        samplesUs = obj.samples_ms.map((x) => Math.round(x * 1000));
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

module.exports = {
  statsFromUs,
  runNativeSweeps,
  runNative,
};
