# SecureDrop Protocol

|                                   | Version           |
| --------------------------------- | ----------------- |
| [Proof-of-Concept] Implementation | 0.1               |
| [Specification]                   | 0.3 ([changelog]) |

[Proof-of-Concept]: ./demo-v0.1/README.md
[changelog]: ./docs/protocol.md#changelog
[specification]: ./docs/protocol.md

## Status

> [!WARNING]
> This repository contains proof-of-concept code and is not intended for production use. The protocol details are not yet finalized.

**January 2025:** A formal analysis was performed by
[Luca Maier](https://github.com/lumaier) in
<https://github.com/lumaier/securedrop-formalanalysis> and published as ["A
Formal Analysis of the SecureDrop
Protocol"](https://doi.org/10.3929/ethz-b-000718325), supervised by David Basin,
Felix Linker, and Shannon Veitch in the Information Security Group at ETH
Zürich.

**May 2024:** Proof-of-concept code was [announced publicly](https://securedrop.org/news/introducing-securedrop-protocol/).

**December 2023:** A preliminary cryptographic audit was performed by
[Michele Orrù](https://github.com/mmaker). See
<https://github.com/freedomofpress/securedrop-protocol/issues/36>.

**Jan 2023:** Proof-of-concept implementation work with [Shielder](https://www.shielder.com/) began.

## Background

To better understand the context of this research and the previous steps that led to it, read the following blog posts:

- [Part 1: Future directions for SecureDrop](https://securedrop.org/news/future-directions-for-securedrop/)
- [Part 2: Anatomy of a whistleblowing system](https://securedrop.org/news/anatomy-of-a-whistleblowing-system/)
- [Part 3: How to research your own cryptography and survive](https://securedrop.org/news/how-to-research-your-own-cryptography-and-survive/)
- [Part 4: Introducing SecureDrop Protocol](https://securedrop.org/news/introducing-securedrop-protocol/)

## Setup instructions

Install the Rust toolchain. To view browsable documentation, install `doxygen` and `dot` (Graphviz). Use `make help` from the project root to see available make targets, e.g. to install lint tools, run formatting checks, or build crates.

Lint tools are installed in the `lint-tools` directory to avoid interfering with the user's system dependencies; cargo will suggest adding the directory to your $PATH, but that's not required.

### Benchmarking

The benchmarks were performed on an Apple MacBook Air M4 to assess the protocol's performance on typical consumer hardware. All source code and the Makefile are located in the `securedrop-protocol` subfolder.

**Dependencies** (install via Homebrew unless noted):

- `rustc` 1.92.0 (via rustup)
- Node ≥ 22
- GCC (required for Rust compilation)
- Firefox
- Chrome

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

#### Debugging wasm and benchmarking code

[`wasm-bindgen`](https://crates.io/crates/wasm-bindgen) exposes Rust objects and functions in Javascript in the benchmarking code. If troubleshooting, ensure you are using the same version of the wasm-bindgen cli as is specified in Cargo.toml (`wasm-bindgen -V`).

`wasm-bindgen` requires wrapper classes for Rust objects to marshall in and out of Javascript. If any structs or function signatures that are being used in `www/index.html` (rendering benchmarks) are changed, the corresponding wrapper structs, annotated with `#[wasm_bindgen]`, will need to change accordingly.

If the wasm-compiled Rust code panics, the browser may display a fairly generic/unhelpful message with limited information (for example, `{"error":"unreachable executed"}`). Add the [`console_error_panic_hook`](https://crates.io/crates/console_error_panic_hook) crate and use the `console_error_panic_hook::set_once();` method in a common codepath annotated by `#[wasm-bindgen]` in order to log further information to the browser console. You will also need to temporarily adjust Cargo.toml:

```
[profile.release]
panic = "unwind"

[profile.dev]
panic = "unwind"
```

You may also need to follow the console_error_panic_hook docs to increase the stacktrace lines printed by your browser.
