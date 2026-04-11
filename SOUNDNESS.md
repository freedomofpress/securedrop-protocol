# Formal analysis and verification of the SecureDrop Protocol

> [!NOTE]
> This document is a work in progress. It describes the soundness _goals_ of a
> proof-of-concept implementation. Think of it as a roadmap, not a set of
> conclusions or guarantees already realized.

## Specification

As [specified][spec], the security properties of the SecureDrop Protocol have
been proven with game-based proofs in the computational model in a manuscript
currently (as of March 2026) under peer review. A subset of these properties
have also been [proven in the symbolic model][models] using the Tamarin Prover.

## Implementation

We aim to follow the methodology outlined in Bhargavan et al. (2025), ["Formal
Security and Functional Verification of Cryptographic Protocol Implementations
in Rust"][bhargavan-2025], to use [hax] and F\* to prove that the Rust crate
implementing the core of the SecureDrop Protocol achieves:

1. [ ] panic freedom
2. [ ] unambiguous message-parsing
3. [ ] secret independence and classification.

In addition, we aim to explore the use of hax and other tools to prove:

4. [ ] the absence of timing side channels in specific code paths
5. [ ] conformance of the crate to the security properties proven in the Tamarin
       models.

## Trusted computing base

We necessarily trust:

- the Tamarin Prover
- hax's extraction to F\*
- F\*'s type-checker
- the Rust compiler.

We currently trust third-party dependencies (including crates in the libcrux
family) as described below. We aim to reduce these trust assumptions as we
include more crates in hax extraction.

## Gaps

### First-party code

During implementation, we expect our list of [`HAX_TARGETS`] to grow from the
inside out, from lower- to higher-level components. That is, only crate members
explicitly listed in `HAX_TARGETS` are:

1. extracted by hax into F\*;
2. type-checked in F\* for panic freedom; and
3. verified in F\* for any additional properties we've manually specified.

Eventually, we hope to be able to extract the entirety of the core protocol
crate without exceptions.

### Third-party dependencies

During our own implementation and verification efforts, we will generate F\*
[interfaces] for third-party dependencies to admit their postconditions on which
we depend as preconditions. We will remove these interfaces as it becomes
possible to extract these dependencies into first-class F\* proofs.

In particular, we aim to achieve full extraction without interfaces for the
following crates:[^1]

- `libcrux-aead`
- `libcrux-kem`
- `libcrux-sha3`
- `libcrux-traits`

[^1]: https://github.com/freedomofpress/securedrop-protocol/issues/172

[bhargavan-2025]: https://eprint.iacr.org/2025/980
[hax]: https://github.com/cryspen/hax
[`HAX_TARGETS`]: ./securedrop-protocol/protocol-minimal/Makefile#L1
[interfaces]: ./securedrop-protocol/protocol-minimal/proofs/fstar/models
[models]: https://github.com/freedomofpress/securedrop-protocol-models
[spec]: ./docs/protocol.md
