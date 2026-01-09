const fs = require('fs');
const os = require('os');
const path = require('path');
const kleur = require('kleur');

function rangeSweep(min, max, step) {
  const out = [];
  for (let v = min; v <= max; v += step) out.push(v);
  return out;
}

const stamp = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
};

const ensureDir = (p) => fs.mkdirSync(p, { recursive: true });

function logInfo(...a) {
  console.log(kleur.cyan('[i]'), ...a);
}

function logWarn(...a) {
  console.warn(kleur.yellow('[!]'), ...a);
}

function logErr(...a) {
  console.error(kleur.red('[x]'), ...a);
}

function makeTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

module.exports = {
  rangeSweep,
  stamp,
  ensureDir,
  logInfo,
  logWarn,
  logErr,
  makeTmp,
};
