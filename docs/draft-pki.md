# PKI for SecureDrop: problem statement

## PKI: the status quo

The readme sketches the following PKI scheme for use with the SecureDrop Protocol:

| The party... | ...has the secret key... | ...with the public key... | ...with the signature[^1]... | ...so that...                                       |
| ------------ | ------------------------ | ------------------------- | ---------------------------- | --------------------------------------------------- |
| FPF          | $FPF_{SK}$               | $FPF_{PK}$                | $\bot$                       |
| Newsroom     | $NR_{SK}$                | $NR_{PK}$                 | $sig^{FPF_{SK}}(NR_{PK})$    | FPF can attest to an instance's legitimacy.[^2]     |
| Journalist   | $J_{SK}$                 | $J_{PK}$                  | $sig^{NR_{SK}}(J_{PK})$      | a source can verify a journalist's enrollment.      |
| Journalist   | $JC_{SK}$                | $JC_{PK}$                 | $sig^{J_{SK}}(JC_{PK})$      | the server can verify a journalist's fetching key.  |
| Journalist   | $JE_{SK}$                | $JE_{PK}$                 | $sig^{J_{SK}}(JE_{PK})$      | a source can verify a journalist's per-message key. |

@mmaker described the need for

> A section dedicated to how keys should be handled [that] will help preventing
> errors in deployments. For example, the FPF could implement canaries to alert
> users of potential compromises; Newsrooms should adhere to a minimal set of
> rules of key rotation and identity validation for journalists, and
> accountability that they still possess the key from time to time.[^3]

@lsd-cat captured other considerations in [#32] and [#54].

The PKI approach has obvious precedent, and its advantages are well understood.
However, it has the disadvantage of making FPF both a bottleneck (operationally)
and a target (for attacks). Consider our current deployment of
[`freedomofpress/securedrop-https-everywhere-ruleset`][sdher]. FPF can _delay_
an update of (e.g.) `nytimes.securedrop.tor.onion` →
`ej3kv4ebuugcmuwxctx5ic7zxh73rnxt42soi3tdneu2c2em55thufqd.onion`, and a
_compromise_ of FPF could result in a corrupted ruleset with
`nytimes.securedrop.tor.onion` → _somewhere else_. But FPF can't do anything to
get in the way of
`ej3kv4ebuugcmuwxctx5ic7zxh73rnxt42soi3tdneu2c2em55thufqd.onion` itself.

In this PKI scheme, by contrast, an operational or security failure at FPF could
lead to (e.g.) all SecureDrop instances being flagged as corrupted or
nonfunctional, just like your favorite CA-based failure mode.

## Key transparency

Orthogonal to (that is, with or without) any PKI, the SecureDrop Protocol could
be deployed using key transparency. The IETF's Key Transparency Working Group
gives these goals for a key-transparency system:

> - Allow an end-user to search and download the public keys of themselves or
>   for other end-users; and enable a process for updating their public key with the
>   authentication service of the communication service provider
>
> - Allow end-users to verify on an ongoing basis that they have a globally
>   consistent view of which public keys have been associated with which accounts,
>   including their own.
>
> - Allow end-users to perform this verification of a globally consistent view
>   via an out-of-band mechanism for small groups, or use an anonymous check with
>   the communication service provider in-band for larger groups.[^4]

The advantages of key transparency (KT) are:

1. **Orthogonality:** KT could be deployed either in addition to or instead of PKI.

2. **Path-independence:** KT could be deployed at any time, again either
   supplementing or replacing existing PKI.

3. **Self- and mutual verification** as described above. Put another way, the
   responsibility for KT could be shared among FPF, organizations with SecureDrops,
   and even partner organizations. For example, a KT failure is a de facto
   "canary" of the sort described by @mmaker above.

The disadvantages of KT are:

1. **Novelty:** KT is under active research, development and standardization,
   and its security guarantees are still being proven.

2. **Operational implications:** KT is another service to run, with new failure
   modes to reason about and manage.

[^1]:
    See
    <https://github.com/freedomofpress/securedrop-protocol?tab=readme-ov-file#functions>
    for the notation used here.

[^2]:
    One reviewer has suggested including a countersignature
    $sig^{NR_{SK}}(FPF_{PK})$.

[^3]: https://github.com/freedomofpress/securedrop-poc/files/14903819/securedrop.report.pdf
[^4]: https://datatracker.ietf.org/wg/keytrans/about/

[#32]: https://github.com/freedomofpress/securedrop-protocol/issues/32
[#54]: https://github.com/freedomofpress/securedrop-protocol/issues/54
[sdher]: https://github.com/freedomofpress/securedrop-https-everywhere-ruleset
