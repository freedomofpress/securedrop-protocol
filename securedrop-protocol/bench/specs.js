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
    u.set('raw', 'json'); // page emits JSON & window.benchResults*
    u.set('quiet', '1'); // no pretty printing
    return `?${u.toString()}`;
  }
}

function defaultSpecs(iterations, k, j, rngOn) {
  return [
    new BenchmarkSpec('encrypt', { n: iterations, k, include_rng: rngOn }),
    new BenchmarkSpec('decrypt_journalist', { n: iterations, k }),
    new BenchmarkSpec('decrypt_source', { n: iterations, k: 1 }),
    new BenchmarkSpec('fetch', { n: iterations, k, j }),
  ];
}

module.exports = {
  BenchmarkSpec,
  defaultSpecs,
};
