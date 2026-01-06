const yargs = require('yargs');
const { hideBin } = require('yargs/helpers');
const { z } = require('zod');

const CliSchema = z.object({
  iterations: z.number().int().positive().default(100),
  browser: z.enum(['chromium', 'firefox', 'all', 'none']).default('all'),
  native: z.enum(['on', 'off']).default('on'),
  flavors: z.string().default('all'),
  mode: z.enum(['warm', 'profile', 'worker']).default('warm'),
  k: z.number().int().nonnegative().default(500),
  j: z.number().int().nonnegative().default(3000),
  rng: z.enum(['on', 'off']).default('off'),
  out: z.string().default('out'),
  root: z.string().default(process.cwd()),
  j_min: z.number().int().nonnegative().nullable().default(null),
  j_max: z.number().int().nonnegative().nullable().default(null),
  j_step: z.number().int().positive().nullable().default(null),
  k_min: z.number().int().nonnegative().nullable().default(null),
  k_max: z.number().int().nonnegative().nullable().default(null),
  k_step: z.number().int().positive().nullable().default(null),
  fetch_sweep_only: z.boolean().default(false),
  decryptj_sweep_only: z.boolean().default(false),
  sweeps_only: z.boolean().default(false),
});

function parseCli(argvInput = process.argv) {
  const argv = yargs(hideBin(argvInput))
    .option('iterations', { alias: 'n', type: 'number', describe: 'Iterations per bench' })
    .option('browser', { type: 'string', describe: 'chromium|firefox|all|none' })
    .option('native', { type: 'string', describe: 'on|off' })
    .option('flavors', { type: 'string', describe: 'all or comma list (chrome,chrome-beta,chrome-dev,firefox,firefox-beta,firefox-nightly,bundled)' })
    .option('mode', { type: 'string', describe: 'warm|profile|worker' })
    .option('k', { type: 'number', describe: 'Keybundles per journalist' })
    .option('j', { type: 'number', describe: 'Challenges per iter (fetch)' })
    .option('rng', { type: 'string', describe: 'Include RNG time inside encrypt loop (on|off)' })
    .option('out', { type: 'string', describe: 'Output directory root' })
    .option('root', { type: 'string', describe: 'Static server root (contains /www/index.html)' })
    .option('j-min', { type: 'number', describe: 'Min challenges for fetch sweep' })
    .option('j-max', { type: 'number', describe: 'Max challenges for fetch sweep' })
    .option('j-step', { type: 'number', describe: 'Step size for fetch sweep' })
    .option('k-min', { type: 'number', describe: 'Min keybundles for decrypt_j sweep' })
    .option('k-max', { type: 'number', describe: 'Max keybundles for decrypt_j sweep' })
    .option('k-step', { type: 'number', describe: 'Step size for decrypt_j sweep' })
    .option('fetch-sweep-only', { type: 'boolean', default: false, describe: 'Run only the fetch sweep' })
    .option('decryptj-sweep-only', { type: 'boolean', default: false, describe: 'Run only the decrypt_journalist sweep' })
    .option('sweeps-only', { type: 'boolean', default: false, describe: 'Run only sweeps (both j- and k-sweeps)' })
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
    j_min: argv['j-min'] ?? null,
    j_max: argv['j-max'] ?? null,
    j_step: argv['j-step'] ?? null,
    k_min: argv['k-min'] ?? null,
    k_max: argv['k-max'] ?? null,
    k_step: argv['k-step'] ?? null,
    fetch_sweep_only: argv['fetch-sweep-only'] ?? false,
    decryptj_sweep_only: argv['decryptj-sweep-only'] ?? false,
    sweeps_only: argv['sweeps-only'] ?? false,
  });

  const RUN_FETCH_SWEEP = cfg.sweeps_only || cfg.fetch_sweep_only;
  const RUN_DECRYPTJ_SWEEP = cfg.sweeps_only || cfg.decryptj_sweep_only;
  const RUN_ANY_SWEEP = RUN_FETCH_SWEEP || RUN_DECRYPTJ_SWEEP;
  const RUN_BASIC = !RUN_ANY_SWEEP;

  return {
    cfg,
    runFlags: {
      RUN_FETCH_SWEEP,
      RUN_DECRYPTJ_SWEEP,
      RUN_ANY_SWEEP,
      RUN_BASIC,
    },
  };
}

module.exports = {
  parseCli,
};
