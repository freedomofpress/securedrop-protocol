#!/usr/bin/env node
import fs from "fs";

function parseCSV(raw) {
  const lines = raw.trim().split(/\r?\n/);
  const header = lines.shift().split(",");
  return lines.map((line) => {
    const cols = line.split(",");
    const obj = {};
    header.forEach((h, i) => (obj[h] = cols[i] || ""));
    return obj;
  });
}

const mean = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
const stddev = (arr) =>
  Math.sqrt(mean(arr.map((x) => (x - mean(arr)) ** 2)));

function computeStats(rows) {
  const map = {};
  for (const r of rows) {
    let bench = r.bench;
    if (bench === "fetch") bench = "solve";

    const fam = r.family;
    const ms = Number(r.sample_us) / 1000;

    if (!map[bench]) map[bench] = {};
    if (!map[bench][fam]) map[bench][fam] = [];
    map[bench][fam].push(ms);
  }

  const out = {};
  for (const bench of Object.keys(map)) {
    out[bench] = {};
    for (const fam of Object.keys(map[bench])) {
      const arr = map[bench][fam];
      out[bench][fam] = {
        mean: mean(arr),
        std: stddev(arr),
      };
    }
  }
  return out;
}

const infile = process.argv[2];
if (!infile) {
  console.error("Usage: node tikzplot.js our/<date>/all_samples.csv");
  process.exit(1);
}

const rows = parseCSV(fs.readFileSync(infile, "utf8"));
const stats = computeStats(rows);

const benches = ["encrypt", "decrypt", "solve"];

const series = [
  { fam: "native",   label: "Native",   fill: "barred"   },
  { fam: "chromium", label: "Chromium", fill: "barblue"  },
  { fam: "firefox",  label: "Firefox",  fill: "bargreen" },
];

console.log(`
\\begin{tikzpicture}[scale=0.8]
\\begin{axis}[
    ybar,
    bar width=4pt,
    ylabel={Timing (ms)},
    ylabel near ticks,
    xlabel={Operation},
    symbolic x coords={encrypt, decrypt, solve},
    xtick=data,
    xtick style={draw=none},
    ytick={0,1,2,3,4,5,6,7},
    minor y tick num=1,
    ymajorgrids=true,
    yminorgrids=true,
    grid style={dotted},
    minor grid style={dotted},
    ymin=0,
    tick style={line width=0.5pt},
    width=5.8cm,
    height=5cm,
    error bars/y dir=both,
    error bars/y explicit,
    legend style={
        at={(0.5,1.05)},
        anchor=south,
        legend columns=3,
        font=\\large,
        draw=none
    },
    legend image code/.code={
        \\draw[#1] (0cm,-0.1cm) rectangle (0.3cm,0.1cm);
    }
]
`);

for (const s of series) {
  console.log(`
\\addplot+[
    fill=${s.fill},
    draw=${s.fill},
    line width=0pt,
    error bars/.cd,
      y dir=both, y explicit,
      error bar style={line width=0.25pt, draw=black},
      error mark options={draw=black, line width=0.25pt, mark size=1pt},
      error mark=|,
] coordinates {
`);

  for (const bench of benches) {
    const st = stats[bench]?.[s.fam];
    if (!st) continue;
    console.log(
      `    (${bench}, ${st.mean.toFixed(3)}) +- (0, ${st.std.toFixed(3)})`
    );
  }

  console.log("};");
}

console.log(`
\\legend{Native, Chromium, Firefox}
\\end{axis}
\\end{tikzpicture}
`);

