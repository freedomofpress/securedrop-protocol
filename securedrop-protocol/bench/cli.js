const yargs = require('yargs');
const { hideBin } = require('yargs/helpers');
const { z } = require('zod');

const CliSchema = z.object({
  iterations: z.number().int().positive().default(100),
  browser: z.enum(['chromium', 'firefox', 'all', 'none']).default('all'),
  native: z.enum(['on', 'off']).default('on'),
  flavors: z.string().default('all'),
  mode: z.enum(['warm', 'profile']).default('warm'),
  k: z.number().int().nonnegative().default(500),
  j: z.number().int().nonnegative().default(1),
  rng: z.enum(['on', 'off']).default('off'),
  iter_timeout: z.number().int().positive().default(120), // seconds, per profile iteration
  attempts: z.number().int().positive().default(3), // retries per profile iteration on hang/error
  strict: z.boolean().default(false), // treat driver/browser startup failures as fatal
  out: z.string().default('out'),
  root: z.string().default(process.cwd()),
  j_min: z.number().int().nonnegative().nullable().default(null),
  j_max: z.number().int().nonnegative().nullable().default(null),
  j_step: z.number().int().positive().nullable().default(null),
  k_min: z.number().int().nonnegative().nullable().default(null),
  k_max: z.number().int().nonnegative().nullable().default(null),
  k_step: z.number().int().positive().nullable().default(null),
  fetch_sweep_only: z.boolean().default(false),
  decrypt_sweep_only: z.boolean().default(false),
  sweeps_only: z.boolean().default(false),
});

function parseCli(argvInput = process.argv) {
  const argv = yargs(hideBin(argvInput))
    .option('iterations', { alias: 'n', type: 'number', describe: 'Iterations per bench' })
    .option('browser', { type: 'string', describe: 'chromium|firefox|all|none' })
    .option('native', { type: 'string', describe: 'on|off' })
    .option('flavors', { type: 'string', describe: 'all or comma list (chrome,chrome-beta,chrome-dev,firefox,firefox-beta,firefox-nightly,bundled)' })
    .option('mode', { type: 'string', describe: 'warm|profile' })
    .option('k', { type: 'number', describe: 'Keybundles per journalist' })
    .option('j', { type: 'number', describe: 'Challenges per iter (fetch)' })
    .option('rng', { type: 'string', describe: 'Include RNG time inside encrypt loop (on|off)' })
    .option('iter-timeout', { type: 'number', describe: 'Per-iteration timeout in seconds (profile mode); a hung iteration is retried (default 120)' })
    .option('attempts', { type: 'number', describe: 'Attempts per profile iteration before failing (default 3)' })
    .option('strict', { type: 'boolean', default: false, describe: 'Fail (exit 1) if a browser/driver never starts after retries (default: non-fatal)' })
    .option('out', { type: 'string', describe: 'Output directory root' })
    .option('root', { type: 'string', describe: 'Static server root (contains /www/index.html)' })
    .option('j-min', { type: 'number', describe: 'Min challenges for fetch sweep' })
    .option('j-max', { type: 'number', describe: 'Max challenges for fetch sweep' })
    .option('j-step', { type: 'number', describe: 'Step size for fetch sweep' })
    .option('k-min', { type: 'number', describe: 'Min keybundles for decrypt sweep' })
    .option('k-max', { type: 'number', describe: 'Max keybundles for decrypt sweep' })
    .option('k-step', { type: 'number', describe: 'Step size for decrypt sweep' })
    .option('fetch-sweep-only', { type: 'boolean', default: false, describe: 'Run only the fetch sweep' })
    .option('decrypt-sweep-only', { type: 'boolean', default: false, describe: 'Run only the decrypt sweep' })
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
    iter_timeout: argv['iter-timeout'],
    attempts: argv.attempts,
    strict: argv.strict,
    out: argv.out,
    root: argv.root,
    j_min: argv['j-min'] ?? null,
    j_max: argv['j-max'] ?? null,
    j_step: argv['j-step'] ?? null,
    k_min: argv['k-min'] ?? null,
    k_max: argv['k-max'] ?? null,
    k_step: argv['k-step'] ?? null,
    fetch_sweep_only: argv['fetch-sweep-only'] ?? false,
    decrypt_sweep_only: argv['decrypt-sweep-only'] ?? false,
    sweeps_only: argv['sweeps-only'] ?? false,
  });

  const RUN_FETCH_SWEEP = cfg.sweeps_only || cfg.fetch_sweep_only;
  const RUN_DECRYPT_SWEEP = cfg.sweeps_only || cfg.decrypt_sweep_only;
  const RUN_ANY_SWEEP = RUN_FETCH_SWEEP || RUN_DECRYPT_SWEEP;
  const RUN_BASIC = !RUN_ANY_SWEEP;

  return {
    cfg,
    runFlags: {
      RUN_FETCH_SWEEP,
      RUN_DECRYPT_SWEEP,
      RUN_ANY_SWEEP,
      RUN_BASIC,
    },
  };
}

module.exports = {
  parseCli,
};
