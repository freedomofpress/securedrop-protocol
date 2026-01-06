const ss = require('simple-statistics');

function prettyStatsFromUs(samplesUs) {
  const ms = samplesUs.map((us) => us / 1000);
  const s = ms.slice().sort((a, b) => a - b);
  return {
    n: s.length,
    total_ms: ss.sum(s),
    avg_ms: ss.mean(s),
    min_ms: s[0] ?? 0,
    p50_ms: ss.quantileSorted(s, 0.5),
    p90_ms: ss.quantileSorted(s, 0.9),
    p99_ms: ss.quantileSorted(s, 0.99),
    max_ms: s[s.length - 1] ?? 0,
  };
}

function makeTable(headers, rows) {
  const Table = require('cli-table3');
  const t = new Table({ head: headers });
  rows.forEach((r) => t.push(r));
  return t.toString();
}

module.exports = {
  prettyStatsFromUs,
  makeTable,
};
