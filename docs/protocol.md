# SecureDrop Protocol specification

> [!NOTE]
> Except where indicated, this document follows the notation and other
> conventions used in Luca Maier's ["Formal Analysis of the SecureDrop
> Protocol"](https://github.com/lumaier/securedrop-formalanalysis).

![chart](../imgs/sd_schema.png)

For simplicity, in this chart, messages are sent to a single _Journalist_ rather than to all journalists enrolled with a given newsroom, and the attachment submission and retrieval procedure is omitted.

## Keys

<!--
TODO: Not yet accounted for from Maier:
- **FPF**:
  - _FPF<sub>SK</sub>_: Long term FPF signing private key
  - _FPF<sub>PK</sub>_: Long term FPF signing public key
- **Server**:
  - _RE<sub>SK</sub>_: Ephemeral Server, per-request message-fetching private key
  - _RE<sub>PK</sub>_: Ephemeral Server, per-request message-fetching public key
  - _DE<sup>n</sup><sub>PK</sub>_: Per-request, ephemeral decoy public key
-->

In the table below:

- **FIXME:** LaTeX set notation

> For keys, we use the notation $X_{A,B}$, where $X$ represents the key owner
> ($X \in \{NR, J, S\}$ [for newsroom, journalist, and source, respectively]), $A$
> represents the key's usage ($A \in \{pke,sig,fetch,dh\}$), and is prefixed with an
> "e" if the key is ephemeral. $B$ indicates whether the component is private or
> public. For Diffie-Hellman keys $x$, the public component is represented by the
> exponentiation $DH(g, x)$. (Maier §5.4.1)

| Party      | Private Key      | Public Key       | Type          | Usage            | Signed by       |
| ---------- | ---------------- | ---------------- | ------------- | ---------------- | --------------- |
| Newsroom   | $`NR_{sig,sk}`$  | $`NR_{sig,pk}`$  | PPK           | Signing          |                 |
| Journalist | $`J_{sig,sk}`$   | $`J_{sig,pk}`$   | PPK           | Signing          | $`NR_{sig,sk}`$ |
| Journalist | $`J_{fetch,sk}`$ | $`J_{fetch,pk}`$ | DH            | Fetching         | $`NR_{sig,sk}`$ |
| Journalist | $`J_{dh,sk}`$    | $`J_{dh,pk}`$    | DH            | DH-AKEM          | $`NR_{sig,sk}`$ |
| Journalist | $`J_{ekem,sk}`$  | $`J_{ekem,pk}`$  | Ephemeral PPK | KEM<sub>pq</sub> | $`J_{sig,sk}`$  |
| Journalist | $`J_{epke,sk}`$  | $`J_{epke,pk}`$  | Ephemeral PPK | PKE              | $`J_{sig,sk}`$  |
| Journalist | $`J_{edh,sk}`$   | $`J_{edh,pk}`$   | Ephemeral DH  | DH-AKEM          | $`J_{sig,sk}`$  |
| Source     | $`S_{fetch,sk}`$ | $`S_{fetch,pk}`$ | DH            | Fetching         |                 |
| Source     | $`S_{dh,sk}`$    | $`S_{dh,pk}`$    | DH            | DH-AKEM          |                 |
| Source     | $`S_{kem,sk}`$   | $`S_{kem,pk}`$   | PPK           | KEM<sub>pq</sub> |                 |
| Source     | $`S_{pke,sk}`$   | $`S_{pke,pk}`$   | PPK           | PKE              |                 |

## Functions

| Syntax                                                | Description                                                                                                                                                                      |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $`h = \text{Hash}(m)`$                                | Hash message $m$ to digest $h$                                                                                                                                                   |
| $`k \Vert k_1 \Vert \dots \Vert k_n = \text{KDF}(m)`$ | Derive one or more keys $k$ from a message $m$                                                                                                                                   |
| $`\sigma = \text{Sign}(sk, m)`$                       | Sign a message $m$ with the private key $sk$                                                                                                                                     |
| $`b \in {0,1} = \text{Vfy}(pk, m, \sigma)`$           | Verify a message $m$ and a signature $\sigma$ with a public key $pk$                                                                                                             |
| $`(sk, pk) = \text{Gen}()`$                           | Generate keys; for DH-AKEM, $(sk, pk) = (x, g^x)$                                                                                                                                |
| $`(c, K) = \text{AuthEncap}(skS, pkR)`$               | Encapsulate a ciphertext $c$ and a shared secret $K$ using a sender's private key $skS$ and a receiver's public key $pkR$; for DH-AKEM, $(c, K) = (pkE, K) = (pk, K) = (g^x, K)$ |
| $`K = \text{AuthDecap}(skR, pkS, pkE)`$               | Decapsulate a shared secret $K$ using a receiver's private key $skR$, a sender's public key $pkS$, and a ciphertext $c$                                                          |
| $`\text{Discard}(x)`$                                 | Discard some value $x$ from local state/storage                                                                                                                                  |

### HPKE<sup>pq</sup><sub>auth</sub>

| Syntax                                                                              | Description                                                                   |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| $`(skS_{dh}, pkS_{dh}) = \text{Gen}_S()`$                                           | Generate keys for a sender $S$                                                |
| $`((skR_{dh}, skR_{kem}), (pkR_{dh}, pkR_{kem})) = \text{Gen}_R()`$                 | Generate keys for a receiver $R$                                              |
| $`((c_1, c_2), c) = \text{AuthEnc}(skS_{dh}, (pkR_{dh}, pkR_{kem}), m, aad, info)`$ | Encrypt to a receiver $R$ a message $m$ with associated data $aad$ and $info$ |
| $`m = \text{AuthDec}((skR_{dh}, skR_{kem}), pkS_dh, ((c_1, c_2), c), aad, info)`$   | Decrypt from a sender $S$ a message $m$ with associated data $aad$ and $info$ |

### Usage

| Keys                       | Source → Journalist            | Journalist → Source          |
| -------------------------- | ------------------------------ | ---------------------------- |
| $`(skS_{dh}, pkS_{dh})`$   | $`(S_{dh,sk}, S_{dh,pk})`$     | $`(J_{dh,sk}, J_{dh,pk})`$   |
| $`(skR_{dh}, pkR_{dh})`$   | $`(J_{edh,sk}, J_{edh,pk})`$   | $`(S_{dh,sk}, S_{dh,pk})`$   |
| $`(skR_{kem}, pkR_{kem})`$ | $`(J_{ekem,sk}, J_{ekem,pk})`$ | $`(S_{kem,sk}, S_{kem,pk})`$ |

> For messages sent from a source to a journalist, the source is identified by
> $`S_{dh,pk}`$ and utilizes the ephemeral keys $`J_{edh,pk}`$ and $`J_{ekem,pk}`$ to
> encrypt its message. The journalist, in turn, authenticates itself using the
> new long-term key $`J_{dh,pk}`$ and relies on the source's long-term keys
> $`S_{dh,pk}`$ and $`S_{kem,pk}`$ to encrypt messages back to the source securely.
> (Maier §5.2)

## Setup

### FPF

| FPF                                                           |
| ------------------------------------------------------------- |
| $`(FPF_{sig,sk}, FPF_{sig,pk}) \leftarrow^{\$} \text{Gen}()`$ |

$FPF_{sig,pk}$ is pinned in all components that participate in the protocol
(likely in a library they share): the server, the journalist client, and the
source client.

### Newsroom

| Newsroom                                                        |                                 | FPF                                                       |
| --------------------------------------------------------------- | ------------------------------- | --------------------------------------------------------- |
| $`(NR_{sig,sk}, NR_{sig,pk}) \longleftarrow^{\$} \text{Gen}()`$ |                                 |                                                           |
|                                                                 | $`\longrightarrow NR_{sig,pk}`$ | for manual verification.                                  |
|                                                                 |                                 | $`\sigma^{FPF} = \text{Sign}(FPF_{sig,sk}, NR_{sig,pk})`$ |
|                                                                 | $`\sigma^{FPF} \longleftarrow`$ |

$NR_{sig,pk}$ and $\sigma^{FPF}$ are pinned in the server during deployment.[^1]

### Journalist

#### Enrollment

| Journalist                                                    |                                                         | Newsroom                                                                                        |
| ------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| $`(J_{sig,sk}, J_{sig,pk}) \leftarrow^{\$} \text{Gen}()`$     |                                                         |                                                                                                 |
| $`(J_{fetch,sk}, J_{fetch,pk}) \leftarrow^{\$} \text{Gen}()`$ |                                                         |                                                                                                 |
| $`(J_{dh,sk}, J_{dh,pk}) \leftarrow^{\$} \text{Gen}()`$       |                                                         |                                                                                                 |
|                                                               | $`\longrightarrow J_{sig,pk}, J_{fetch,pk}, J_{dh,pk}`$ | for manual verification.                                                                        |
|                                                               |                                                         | $`\sigma^{NR} \leftarrow^{\$} \text{Sign}(NR_{sig,sk}, (J_{sig,pk}, J_{fetch,pk}, J_{dh,pk}))`$ |
|                                                               | $`\sigma^{NR} \longleftarrow`$                          |                                                                                                 |

Public keys and $\sigma^{NR}$ are saved to the server.

#### Setup and periodic replenishment of $n$ ephemeral keys

Repeat $n$ times:

| Journalist                                                                                   |
| -------------------------------------------------------------------------------------------- |
| $`(J_{edh,sk}, J_{edh,pk}) \longleftarrow^{\$} \text{Gen}()`$                                |
| $`(J_{ekem,sk}, J_{ekem,pk}) \longleftarrow^{\$} \text{Gen}()`$                              |
| $`(J_{epke,sk}, J_{epke,pk}) \longleftarrow^{\$} \text{Gen}()`$                              |
| $`\sigma^J \leftarrow^{\$} \text{Sign}(J_{sig,sk}, (J_{edh,pk}, J_{ekem,pk}, J_{epke,pk}))`$ |

Public keys and $\sigma^{J}$ are saved to the server.

### Source

After entering (on their first visit) or reentering (on a subsequent visit) some $passphrase$:

| Source                                                                                      |
| ------------------------------------------------------------------------------------------- |
| $`S_{dh,sk} \Vert S_{fetch,sk} \Vert S_{pke,sk} \Vert S_{kem,sk} = \text{KDF}(passphrase)`$ |

## Messaging protocol overview

Only a source can initiate a conversation; there are no other choices as sources
are effectively unknown until they initiate contact first.

### Source fetches keys and verifies their authenticity

For some newsroom $NR$ and all its enrolled journalists $J^i$:

| Source                                                    |                                                                             | Server                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------- |
|                                                           | $\longrightarrow$ request keys for $NR$                                     |                                   |
|                                                           | $`NR_{sig,pk}, \sigma^{FPF} \longleftarrow`$                                |
|                                                           |                                                                             | $`\forall J^i`$:                  |
|                                                           | $`J^i_{sig,pk}, J^i_{fetch,pk}, J^i_{dh,pk}, \sigma^{NR} \longleftarrow`$   |
|                                                           | $`J^i_{edh,pk}, J^i_{ekem,pk}, J^i_{epke,pk}, \sigma^{J^i} \longleftarrow`$ | chosen at random for $J^i$        |
|                                                           |                                                                             | $`\text{Discard}(J^i_{edh,pk})`$  |
|                                                           |                                                                             | $`\text{Discard}(J^i_{ekem,pk})`$ |
|                                                           |                                                                             | $`\text{Discard}(J^i_{epke,pk})`$ |
| $`\text{Vfy}(FPF_{sig,pk}, NR_{sig,pk}, \sigma^{FPF})`$   |                                                                             |                                   |
| $`\forall J^i`$:                                          |                                                                             |                                   |
| $`\text{Vfy}(NR_{sig,pk}, J^i_{sig,pk}, \sigma^{NR})`$    |                                                                             |                                   |
| $`\text{Vfy}(NR_{sig,pk}, J^i_{fetch,pk}, \sigma^{NR})`$  |                                                                             |                                   |
| $`\text{Vfy}(NR_{sig,pk}, J^i_{dh,pk}, \sigma^{NR})`$     |                                                                             |                                   |
| $`\text{Vfy}(J^i_{sig,pk}, J^i_{edh,pk}, \sigma^{J^i})`$  |                                                                             |                                   |
| $`\text{Vfy}(J^i_{sig,pk}, J^i_{ekem,pk}, \sigma^{J^i})`$ |                                                                             |                                   |
| $`\text{Vfy}(J^i_{sig,pk}, J^i_{epke,pk}, \sigma^{J^i})`$ |                                                                             |                                   |

### Source submission to Journalist

4.  _Source_ generates the unique passphrase randomly _PW = G()_ (the only state that identifies the specific _Source_)
5.  _Source_ derives _S<sub>SK</sub> = G(KDF(encryption_salt + PW))_, _S<sub>PK</sub> = GetPub(S<sub>SK</sub>)_
6.  _Source_ derives _SC<sub>SK</sub> = G(KDF(fetching_salt + PW))_, _SC<sub>PK</sub> = GetPub(SC<sub>SK</sub>)_
7.  _Source_ splits any attachment in parts of size `commons.CHUNKS`. Any chunk smaller is padded to `commons.CHUNKS` size.
8.  For every _Chunk_, _<sup>m</sup>u_
    - _Source_ generate a random key _<sup>m</sup>s = G()_
    - _Source_ encrypts _<sup>m</sup>u_ using _<sup>m</sup>s_: _<sup>m</sup>f = E(<sup>m</sup>s, <sup>m</sup>u)_
    - _Source_ uploads _<sup>m</sup>f_ to _Server_, which returns a random token <sup>m</sup>t (`file_id`)
    - _Server_ stores <sup>m</sup>t -> _<sup>m</sup>f_ (`file_id` -> `file`)
9.  _Source_ adds metadata, _S<sub>PK</sub>_, _SC<sub>PK</sub>_ to message _m_.
10. _Source_ adds all the _<sup>[0-m]</sup>s_ keys and all the tokens <sup>[0-m]</sup>t (`file_id`) to message _m_
11. _Source_ pads the resulting text to a fixed size: _mp = Pad(message, metadata, S<sub>PK</sub>, SC<sub>PK</sub>, <sup>[0-m]</sup>s, <sup>[0-m]</sup>t)_
12. For every _Journalist_ (i) in _Newsroom_
    - _Source_ generates _<sup>i</sup>ME<sub>SK</sub> = Gen()_ (random, per-message secret key)
    - _Source_ derives the corresponding public key _<sup>i</sup>ME<sub>PK</sub> = GetPub(<sup>i</sup>ME<sub>SK</sub>)_ (`message_public_key`)
    - _Source_ derives the shared encryption key using a key-agreement primitive _<sup>i</sup>k = DH(<sup>i</sup>ME<sub>SK</sub>,<sup>i</sup>JE<sub>PK</sub>)_
    - _Source_ encrypts _mp_ using _<sup>i</sup>k_: _<sup>i</sup>c = Enc(<sup>i</sup>k, mp)_ (`message_ciphertext`)
    - _Source_ calculates _mgdh = DH(<sup>i</sup>ME<sub>SK</sub>,<sup>i</sup>JC<sub>PK</sub>)_ (`message_gdh`)
    - _Source_ discards <sup>i</sup>ME<sub>SK</sub> to ensure forward secrecy
    - _Source_ sends _(<sup>i</sup>c,<sup>i</sup>ME<sub>PK</sub>,<sup>i</sup>mgdh)_ to _Server_
    - _Server_ generates _<sup>i</sup>mid = Gen()_ (`message_id`) and stores _<sup>i</sup>mid_ -> _(<sup>i</sup>c,<sup>i</sup>ME<sub>PK</sub>,<sup>i</sup>mgdh)_ (`message_id` -> (`message_ciphertext`, `message_public_key`, `message_gdh`))

### Server message id fetching protocol

1. For every entry _<sup>i</sup>mid_ -> _<sup>i</sup>ME<sub>PK</sub>_, _<sup>i</sup>mgdh_ (`message_id` -> (`message_gdh`, `message_public_key`)):
   - _Server_ generates per-request, per-message, ephemeral secret key _<sup>i</sup>RE<sub>SK</sub> = Gen()_
   - _Server_ calculates _<sup>i</sup>kmid = DH(<sup>i</sup>RE<sub>SK</sub>,<sup>i</sup>mgdh)_
   - _Server_ calculates _<sup>i</sup>pmgdh = DH(<sup>i</sup>RE<sub>SK</sub>,<sup>i</sup>ME<sub>PK</sub>)_
   - _Server_ encrypts _<sup>i</sup>mid_ using _<sup>i</sup>kmid_: _<sup>i</sup>enc_mid = Enc(<sup>i</sup>kmid, <sup>i</sup>mid)_
   - _Server_ discards _<sup>i</sup>RE<sub>SK</sub>_
2. _Server_ generates _j = [`commons.MAX_MESSAGES - i`]_ random decoys _<sup>[0-j]</sup>decoy_pmgdh_ and _<sup>[0-j]</sup>decoy_enc_mid_
3. _Server_ returns a shuffled list of `commons.MAX_MESSAGES` (_i+j_) tuples of _(<sup>[0-i]</sup>pmgdh,<sup>[0-i]</sup>enc_mid) U (<sup>[0-j]</sup>decoy_pmgdh,<sup>[0-j]</sup>enc_mid)_

### Source message id fetching protocol

1. _Source_ derives _SC<sub>SK</sub> = G(KDF(fetching_salt + PW))_
2. _Source_ fetches _(<sup>[0-n]</sup>pmgdh,<sup>[0-n]</sup>enc_mid)_ from _Server_ (`n=commons.MAX_MESSAGES`)
3. For every _(<sup>i</sup>pmgdh,<sup>i</sup>enc_mid)_:
   - _Source_ calculates _<sup>i</sup>kmid = DH(<sup>i</sup>pmgdh,SC<sub>SK</sub>)_
   - _Source_ attempts to decrypt _<sup>i</sup>mid = Dec(<sup>i</sup>kmid,<sup>i</sup>enc_mid)_
   - If decryption succeeds, save _<sup>i</sup>mid_

### Journalist message id fetching protocol

1. _Journalist_ fetches _(<sup>[0-n]</sup>pmgdh,<sup>[0-n]</sup>enc_mid)_ from _Server_ (`n=commons.MAX_MESSAGES`)
2. For every _(<sup>i</sup>pmgdh,<sup>i</sup>enc_mid)_:
   - _Journalist_ calculates _<sup>i</sup>kmid = DH(<sup>i</sup>pmgdh,JC<sub>SK</sub>)_
   - _Journalist_ attempts to decrypt _<sup>i</sup>mid = Dec(<sup>i</sup>kmid,<sup>i</sup>enc_mid)_
   - If decryption succeeds, save _<sup>i</sup>mid_

### Journalist read

1.  _Journalist_ fetches from _Server_ _mid_ -> (_c_, _ME<sub>PK</sub>_) (`message_id` -> (`message_ciphertext`, `message_public_key`))
2.  For every unused _Journalist_ ephemeral key _<sup>i</sup>JE<sub>SK</sub>_
    - _Journalist_ calculates a tentative encryption key using the key agreemenet primitive _<sup>i</sup>k = DH(<sup>i</sup>JE<sub>SK</sub>, ME<sub>PK</sub>)_
    - _Journalist_ attempts to decrypt _mp = Dec(<sup>i</sup>k, c)_
    - _Journalist_ verifies that _mp_ decrypted successfully, if yes exits the loop
3.  _Journalist_ removes padding from the decrypted message: *(message, metadata, *S<sub>PK</sub>*, *SC<sub>PK</sub>_, _<sup>[0-m]</sup>s*, *<sup>[0-m]</sup>t*) = Unpad(mp)*
4.  For every attachment _Chunk_ token _<sup>m</sup>t_
    - _Journalist_ fetches from _Server_ _<sup>m</sup>t_ -> _<sup>m</sup>f_ (`file_id` -> `file`)
    - _Journalist_ decrypts _<sup>m</sup>f_ using _<sup>m</sup>s_: _<sup>m</sup>u = Dec(<sup>m</sup>s, <sup>m</sup>)f_
5.  _Journalist_ joins _<sup>m</sup>u_ according to metadata and saves back the original files
6.  _Journalist_ reads the message _m_

### Journalist reply

1.  _Journalist_ has plaintext _mp_, which contains also _S<sub>PK</sub>_ and SC<sub>PK</sub>
2.  _Journalist_ generates _ME<sub>SK</sub> = Gen()_ (random, per-message secret key)
3.  _Journalist_ derives the shared encryption key using a key-agreement primitive _k = DH(ME<sub>SK</sub>,S<sub>PK</sub>)_
4.  _Journalist_ pads the text to a fixed size: _mp = Pad(message, metadata)_ (note: Journalist can potetially attach _<sup>r</sup>JE<sub>PK</sub>,JC<sub>PK</sub>_)
5.  _Journalist_ encrypts _mp_ using _k_: _c = Enc(k, mp)_
6.  _Journalist_ calculates _mgdh = DH(ME<sub>SK</sub>,SC<sub>PK</sub>)_ (`message_gdh`)
7.  _Journalist_ discards _ME<sub>SK</sub>_
8.  _Journalist_ sends _(c,ME<sub>PK</sub>,mgdh)_ to _Server_
9.  _Server_ generates _mid = Gen()_ (`message_id`) and stores _mid_ -> _(c,ME<sub>PK</sub>,mgdh)_ (`message_id` -> (`message_ciphertext`, `message_public_key`, `message_gdh`))

### Source read

1.  _Source_ fetches from _Server_ _mid_ -> (_c_, _ME<sub>PK</sub>_) (`message_id` -> (`message_ciphertext`, `message_public_key`))
2.  _Source_ derives _S<sub>SK</sub> = G(KDF(encryption_salt + PW))_
3.  _Source_ calculates the shared encryption key using a key agreement protocol _k = DH(S<sub>SK</sub>, ME<sub>PK</sub>)_
4.  _Source_ decrypts the message using _k_: _mp = Dec(k<sup>k</sup>, c)_
5.  _Source_ removes padding from the decrypted message: _m = Unpad(mp)_
6.  _Source_ reads the message and the metadata

### Source reply

_Source_ replies work the exact same way as a first submission, except the source is already known to the _Journalist_. As an additional difference, a _Journalist_ might choose to attach their (and eventually others') keys in the reply, so that _Source_ does not have to fetch those from the server as in a first submission.

[^1]: See [`draft-pki.md`](./draft-pki.md) for further considerations.
