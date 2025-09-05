#!/usr/bin/env node
/* bench.js
 *
 * Usage:
 *   node bench.js -n 500                   # native + chromium + firefox
 *   node bench.js --browser chromium -n 250
 *   node bench.js --browser all --native off -n 100
 */

const { chromium, firefox } = require('playwright');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function parseArgs(argv) {
  let iterations = 100;
  let browserSel = 'all';          // chromium|firefox|all|none
  let nativeSel = 'on';            // on|off
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if ((a === '-n' || a === '--iterations') && i + 1 < argv.length) {
      iterations = parseInt(argv[++i], 10);
      if (!Number.isFinite(iterations) || iterations <= 0) {
        console.error(`Invalid iterations: ${argv[i]}`);
        process.exit(1);
      }
    } else if (a === '--browser' && i + 1 < argv.length) {
      browserSel = argv[++i];
      if (!['chromium', 'firefox', 'all', 'none'].includes(browserSel)) {
        console.error(`Unknown browser: ${browserSel}`);
        process.exit(1);
      }
    } else if (a === '--native' && i + 1 < argv.length) {
      nativeSel = argv[++i];
      if (!['on', 'off'].includes(nativeSel)) {
        console.error(`--native must be on|off`);
        process.exit(1);
      }
    } else {
      console.error(`Unknown arg: ${a}`);
      console.error('Usage: node bench.js [--browser chromium|firefox|all|none] [--native on|off] [-n|--iterations N]');
      process.exit(1);
    }
  }
  return { iterations, browserSel, nativeSel };
}

function startServer(root) {
  return new Promise(resolve => {
    const server = http.createServer((req, res) => {
      const reqPath = req.url === '/' ? '/www/index.html' : req.url;
      const filePath = path.join(root, reqPath);

      // COOP/COEP for precise timers (high-res performance.now(), SAB, etc.)
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
      res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
      res.setHeader('Timing-Allow-Origin', '*');

      fs.readFile(filePath, (err, data) => {
        if (err) {
          res.statusCode = 404;
          res.end('Not found');
          return;
        }
        const ext = path.extname(filePath).toLowerCase();
        const types = {
          '.html': 'text/html; charset=utf-8',
          '.js':   'application/javascript; charset=utf-8',
          '.mjs':  'application/javascript; charset=utf-8',
          '.wasm': 'application/wasm',
          '.json': 'application/json; charset=utf-8',
          '.css':  'text/css; charset=utf-8'
        };
        res.setHeader('Content-Type', types[ext] || 'application/octet-stream');
        res.end(data);
      });
    }).listen(0, () => resolve(server));
  });
}

function parseNativeOutput(text) {
  // Expect blocks like:
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

    let rec = parsed[m];
    if (!rec) {
      // fallback: single-run stdout with different label
      const firstKey = Object.keys(parsed)[0];
      if (firstKey) rec = parsed[firstKey];
    }
    if (!rec) {
      console.error(`[native ${m}] could not parse output:\n${proc.stdout.toString()}`);
      process.exit(1);
    }
    // Ensure iterations populated; show in the table.
    if (!rec.iterations) rec.iterations = iterations;

    results[key] = rec;
  }
  return results;
}

async function runBrowser(browserType, iterations) {
  const server = await startServer(process.cwd());
  const port = server.address().port;
  const url = `http://localhost:${port}/www/index.html`;

  const browser = await browserType.launch(); // headless by default
  const page = await browser.newPage();
  await page.goto(url, { waitUntil: 'load' });

  const coi = await page.evaluate(() => globalThis.crossOriginIsolated === true);
  if (!coi) {
    console.warn(`[${browserType.name()}] Warning: crossOriginIsolated is false; timers may be coarse.`);
  }

  await page.waitForFunction(() =>
    typeof window.decrypt_bench === 'function' &&
    typeof window.encrypt_bench === 'function' &&
    typeof window.fetch_bench   === 'function' &&
    typeof window.submit_bench  === 'function'
  );

  async function time(fnName) {
    // Small warm-up to JIT & cache (doesn't count).
    await page.evaluate((name) => { window; }, fnName);

    // Timed run
    const res = await page.evaluate(({ name, iters }) => {
      const start = performance.now();
      window[name](iters);
      const totalMs = performance.now() - start;
      const avgUs = (totalMs * 1000) / iters;
      return { totalMs, avgUs };
    }, { name: fnName, iters: iterations });

    return { ...res, iterations };
  }

  const results = {};
  for (const fn of ['encrypt_bench', 'decrypt_bench', 'fetch_bench', 'submit_bench']) {
    results[fn] = await time(fn);
  }

  await browser.close();
  server.close();
  return results;
}

function toFixedSafe(num, digits) {
  if (!Number.isFinite(num)) return String(num);
  return num.toFixed(digits);
}

function makeTable(rows, headers) {
  // rows: array of arrays (strings); headers: array of strings
  const cols = headers.length;
  const widths = new Array(cols).fill(0);
  for (let c = 0; c < cols; c++) {
    widths[c] = Math.max(headers[c].length, ...rows.map(r => String(r[c]).length));
  }
  const pad = (s, w) => String(s).padEnd(w, ' ');
  const line = (ch) => ch.repeat(widths.reduce((a, b) => a + b, 0) + (3 * (cols - 1)));

  let out = '';
  out += headers.map((h, i) => pad(h, widths[i])).join(' | ') + '\n';
  out += line('-') + '\n';
  for (const r of rows) {
    out += r.map((cell, i) => pad(cell, widths[i])).join(' | ') + '\n';
  }
  return out;
}

function printSection(title) {
  console.log(`\n=== ${title} ===`);
}

function buildRows(results, nativeRef) {
  // results: map op -> {totalMs, avgUs, iterations}
  // nativeRef: same shape (or null). Slowdown = avgUs / native.avgUs
  const order = ['encrypt_bench', 'decrypt_bench', 'fetch_bench', 'submit_bench'];
  const prettyName = {
    encrypt_bench: 'encrypt',
    decrypt_bench: 'decrypt',
    fetch_bench:   'fetch',
    submit_bench:  'submit',
  };

  const rows = [];
  for (const op of order) {
    const r = results[op];
    if (!r) continue;
    const iter = r.iterations ?? '';
    const totalMs = toFixedSafe(r.totalMs, 2);
    const avgUs   = toFixedSafe(r.avgUs, 2);
    let slowdown = '';
    if (nativeRef && nativeRef[op] && Number.isFinite(nativeRef[op].avgUs) && nativeRef[op].avgUs > 0) {
      slowdown = 'x' + toFixedSafe(r.avgUs / nativeRef[op].avgUs, 2);
    } else if (!nativeRef) {
      slowdown = 'x1.00';
    }
    rows.push([
      prettyName[op],
      iter,
      totalMs,
      avgUs,
      slowdown || '—',
    ]);
  }
  return rows;
}

(async () => {
  const { iterations, browserSel, nativeSel } = parseArgs(process.argv);

  let native = null;
  if (nativeSel === 'on') {
    native = runNative(iterations);
    printSection('Native (cargo bench)');
    const rows = buildRows(native, null); // slowdown x1.00 shown
    const table = makeTable(rows, ['op', 'iters', 'total (ms)', 'avg (µs/iter)', 'slowdown']);
    process.stdout.write(table);
  }

  const wantChromium = (browserSel === 'chromium' || browserSel === 'all');
  const wantFirefox  = (browserSel === 'firefox'  || browserSel === 'all');

  if (wantChromium) {
    const res = await runBrowser(chromium, iterations);
    printSection(`Chromium (${iterations} iterations)`);
    const rows = buildRows(res, native);
    const table = makeTable(rows, ['op', 'iters', 'total (ms)', 'avg (µs/iter)', 'slowdown vs native']);
    process.stdout.write(table);
  }

  if (wantFirefox) {
    const res = await runBrowser(firefox, iterations);
    printSection(`Firefox (${iterations} iterations)`);
    const rows = buildRows(res, native);
    const table = makeTable(rows, ['op', 'iters', 'total (ms)', 'avg (µs/iter)', 'slowdown vs native']);
    process.stdout.write(table);
  }
})().catch(err => {
  console.error(err);
  process.exit(1);
});
