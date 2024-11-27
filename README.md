*Work in progress*


* [Previous research on how we might integrate a KEM][2024-10-03-update]


[2024-10-03-update]: https://docs.google.com/document/d/15Lmb1wbmTaXA1FmEOrA0OZL1c2x2Ts2j08nNxuyyhKQ/edit


## What is this?

This is a manual fork of
<https://gist.github.com/cfm/dab18074b9cecb06cbd006e1ab7ede7f> plus a KEM.  The
goal to keep this in sync on top of
<https://gist.github.com/cfm/dab18074b9cecb06cbd006e1ab7ede7f> so that a diff
shows *only* KEM-related changes.

```sh-session
$ git clone git@gist.github.com:09f4e5682d3b216762cd878e3a8879f0.git dhetm-kem-securedrop
$ cd dhetm-kem-securedrop/
$ git remote add upstream git@gist.github.com:dab18074b9cecb06cbd006e1ab7ede7f.git
$ git fetch upstream
$ git diff upstream/main
```


## What are we trying to do?

Out of the IETF's Crypto Forum Research Group (CFRG), ["Combiner Functions for
Hybrid Key Encapsulation Mechanisms"][draft-ounsworth-cfrg-kem-combiners] tells
us that

> [t]he need for a KEM combiner function arises in three different contexts
> within IETF security protocols:  (1) [...]; (2) Post-quantum / traditional
> hybrid KEMs where output of a post-quantum KEM is combined with the output of
> a classical key transport or key exchange algorithm.  [...][^1]

The Post-Quantum Use in Protocols Working Group (PQUIP)'s ["Terminology for
Post-Quantum Traditional Hybrid
Schemes"][draft-ietf-pquip-pqt-hybrid-terminology] gives us the relevant
definitions:

> **Post-Quantum Traditional (PQ/T) Hybrid Scheme:**  A multi-algorithm scheme
> where at least one component algorithm is a post-quantum algorithm and at
> least one is a traditional algorithm.[^2]
>
> **PQ/T Hybrid Key Encapsulation Mechanism (KEM):**  A multi-algorithm KEM
> made up of two or more component algorithms where at least one is a
> post-quantum algorithm and at least one is a traditional algorithm. The
> component algorithms could be KEMs, or other key establishment
> algorithms.[^3]

This is important.  We are not merely *adding* a KEM *to* DHETM (a non-KEM key
exchange).  We are effectively transforming DHETM *into* a KEM.

And then "Combiner Functions" gives us the general principle of what we're
doing here:

> A KEM combiner is a function that takes in two or more shared secrets `ss_i`
> and returns a combined shared secret `ss`.
>
>     ss = kemCombiner(ss_1, ss_2, ..., ss_n)
>
> This document assumes that shared secrets are the output of a KEM, but
> without loss of generality they MAY also be any other source of cryptographic
> key material [...].[^4]

In our case, we'll have something like:

```python
ss_1 = DH(...)
ss_2 = DH(...)
ss_3, ct = Encap()  # ct to be dealt with separately
ss = kemCombiner(ss_1, ss_2, ss_3)
```

"Combiner Functions" gives more [guidance][kem-combiner-construction] on how
`kemCombiner()` should be implemented.  Specifically, `kemCombiner()` needs to
be a "split" or "dual" pseudo-random function (PRF).[^5]  For the purpose of
prototyping here, we'll continue to use `kemCombiner() = nacl.hashlib.scrypt()`
and leave open (below) the question of what KDF should be used in
`kemCombiner()`.


[draft-ietf-pquip-pqt-hybrid-terminology]: https://datatracker.ietf.org/doc/html/draft-ietf-pquip-pqt-hybrid-terminology-04

[draft-ounsworth-cfrg-kem-combiners]: https://datatracker.ietf.org/doc/html/draft-ounsworth-cfrg-kem-combiners-05

[kem-combiner-construction]: https://datatracker.ietf.org/doc/html/draft-ounsworth-cfrg-kem-combiners-05#name-kem-combiner-construction

[^1]: https://datatracker.ietf.org/doc/html/draft-ounsworth-cfrg-kem-combiners-05#section-2-2.2.1

[^2]: https://datatracker.ietf.org/doc/html/draft-ietf-pquip-pqt-hybrid-terminology-04#section-2-4.8.1

[^3]: https://datatracker.ietf.org/doc/html/draft-ietf-pquip-pqt-hybrid-terminology-04#section-2-4.10.1

[^4]: https://datatracker.ietf.org/doc/html/draft-ounsworth-cfrg-kem-combiners-05#name-kem-combiner-construction

[^5]: I've started acccumulating citations on this topic in <https://www.anakolouthon.org/pub/reading+lists/cryptography%2C+especially+end-to-end+encryption#Key%20derivation%20and%20combination>.


## Open questions

1. What KDF should be used in `kemCombiner()`?


---

Per <https://gist.github.com/cfm/dab18074b9cecb06cbd006e1ab7ede7f#file-readme-md>:

- [x] key generation
- [x] minimal source encryption → journalist decryption
- [x] ephemeral source encryption → journalist decryption
  - [x] verification of $$J$$ and $$NR$$
- [x] ephemeral journalist encryption → source decryption
- [x] ephemeral journalist encryption → journalist decryption
- [x] ephemeral source encryption → source decryption
- [ ] **KEM:** work in progress
- [ ] restore fetching from <https://gist.github.com/lsd-cat/62b05108d7ed7e974efbb805e35eaf28>
- [x] tracing like <https://gist.github.com/cfm/c63561609d2bf621d877dbbef052ab1a> → <https://gist.github.com/cfm/ddbeec52c65f474ce309cb85ae9617aa>
