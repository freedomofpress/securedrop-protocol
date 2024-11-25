## What is this?

1. <https://gist.github.com/lsd-cat/62b05108d7ed7e974efbb805e35eaf28> is a toy implementation of `freedomofpress/securedrop-protocol` using PQXDH.
2. <https://github.com/freedomofpress/securedrop-protocol/issues/55#issuecomment-2454681466> is Luca Maier's proposal for using Jee Hea An's [https://eprint.iacr.org/2001/079](DHETM) scheme for authentication encryption instead.

This gist takes the approach of (1) to implement (2).  After defining a few helpers for consistency with Luca's notation, we step through each phase of the protocol for each party and implement it, to make sure it works exactly as notated.  (You may find it helpful to clone this gist locally and read through it commit by commit, since the Git history follows the exposition of Luca's proposal.)


---

Per <https://github.com/freedomofpress/securedrop-protocol/issues/55#issuecomment-2454681466>:

- [x] key generation
- [x] minimal source encryption → journalist decryption
- [x] ephemeral source encryption → journalist decryption
  - [x] verification of $$J$$ and $$NR$$
- [x] ephemeral journalist encryption → source decryption
- [x] ephemeral journalist encryption → journalist decryption
- [x] ephemeral source encryption → source decryption
- [ ] KEM
- [ ] restore fetching from <https://gist.github.com/lsd-cat/62b05108d7ed7e974efbb805e35eaf28>
- [x] tracing like <https://gist.github.com/cfm/c63561609d2bf621d877dbbef052ab1a> → <https://gist.github.com/cfm/ddbeec52c65f474ce309cb85ae9617aa>