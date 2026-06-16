## Setup instructions

On Ubuntu 24.04 or Mac (Apple Silicon) with Homebrew, run:

```bash
make setup
```

This detects the OS and installs all system-level prerequisites automatically (Node 22, the Rust toolchain via `rustup`, the wasm target, and the required browser libraries). It needs `sudo` on Linux and Homebrew on macOS.

### Benchmarking

The benchmarks were performed on an Apple MacBook Air M4 to assess the protocol's performance on typical consumer hardware.

Run a quick sanity‑check with a few iterations:

```bash
make quick-bench
```

Run the full benchmark suite:

```bash
make bench
```

Two benchmark types are implemented: iterative benchmarks and sweep benchmarks. The iterative benchmark measures three core protocol operations:

- **encrypt** – encrypt a payload
- **decrypt** – decrypt using a single key bundle
- **solve** – solve a single challenge

These operations provide the baseline for the iterative and configurable protocol functions. For example, a _Journalist decrypt_ repeatedly calls the decrypt primitive for all currently active Journalist key bundles, while a _retrieve_ runs the solve function on every challenge returned by the server.

Sweep benchmarks evaluate client performance as configurable system parameters grows. One sweep measures the journalist‑decrypt function while increasing the number of active key bundles; the other measures the retrieve operation as the maximum number of system messages grows. As expected, runtimes scale roughly linearly, but WebAssembly optimisations can become significant when the number of iterations grows and the startup cost is amortised.

Results are saved in the `out` directory in both JSON and CSV formats. By default each benchmark iteration uses a fresh browser profile. The underlying Node script also supports a mode that runs without restarting the browser, looping over the WebAssembly functions. This mode yields extremely fast numbers in some cases because of optimisations and predictions that would not occur in real‑world usage, and therefore can produce misleading results.

Browser benchmarks are inherently flaky, so a hung or failed iteration is retried automatically. You may therefore see yellow `[!]` warnings during a run (for example `Retrying profile …`, a `driver.quit()` that had to be force‑killed, or a native bench that produced no samples); these are non‑fatal and the run still completes. 

##### Charts

A TikZ chart of the iterative benchmark is generated automatically at the end of every run and written to `chart.tex` in the run's output folder (for example `out/20260112-222635/chart.tex`), ready to include in a LaTeX document. If chart generation fails it prints a `Chart generation failed` warning but does not fail the run.

You can also regenerate the chart manually from a previous run's samples:

```bash
node chart.js out/20260112-222635/all_samples.csv
```

This prints the TikZ code to the console.
