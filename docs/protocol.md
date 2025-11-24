# SecureDrop Protocol specification

| Version |
| ------- |
| 0.3     |

> [!NOTE]
> The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
> RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
> described in [RFC 2119].

<!-- TODO: update v0.2 → v0.3

## Overview

This sequence diagram shows the flow of messages and values in the SecureDrop
Protocol. The yellow boxes correspond to sections in the specification below
that describe how these values are constructed and consumed.

```mermaid
sequenceDiagram

actor Source

box News Organization
participant Server
actor Journalist
participant Newsroom
end

participant FPF

Note over Newsroom, FPF: 2. Newsroom setup
activate FPF
activate Newsroom
Newsroom ->> FPF: NRsig,pk := newsroom's signing key
FPF ->> Newsroom: σFPF := FPF's signature
deactivate FPF
activate Server

Note over Journalist, Server: 3.1. Journalist enrollment
activate Journalist
Journalist ->> Newsroom: Jsig,pk := journalist's signing key
Newsroom ->> Journalist: σNR := newsroom's signature on Jsig,pk
Journalist ->> Journalist: J{fetch,dh},pk := journalist's long-term keys
Journalist ->> Journalist: σJ := signature over J{fetch,dh},pk using Jsig,sk
Journalist ->> Server: J{sig,fetch,dh},pk<br>σNR, σJ
deactivate Newsroom

Note over Journalist, Server: 3.2. Setup and periodic replenishment<br>of n ephemeral keys
loop forall n:
Journalist ->> Server: J{edh,ekem,epke},pk := journalist's ephemeral keys<br>σJ := journalist's signature
end

Note over Source: 4. Source setup
Source ->> Source: passphrase

alt Source → Journalist
Note over Source, Server: 5. Source fetches keys and verifies<br>their authenticity
activate Source
Source ->> Server: request keys for newsroom
Server ->> Source: NRsig,pk<br>σFPF
loop forall journalists J:
Server ->> Source: J{sig,fetch,dh},pk<br>σNR<br>J{edh,ekem,epke},pk<br>σJ
end

Note over Source, Server: 6. Source submits a message
loop forall journalists J:
Source ->> Server: C := message ciphertext<br>Z := public key<br>X := Diffie-Hellman share
end

Note over Server, Journalist: 7. Journalist fetches message IDs
Journalist ->> Server: request messages
loop forall n  messages:
Server ->> Journalist: Q0...n := public keys<br>cid0...n := encrypted message IDs
end

Note over Server, Journalist: 8. Journalist fetches and decrypts a message
Journalist ->> Server: id := decrypted message ID
Server ->> Journalist: C

else Journalist → Source
Note over Server, Journalist: 9. Journalist replies to a source
Journalist ->> Server: C' := message ciphertext<br>Z' := public key<br>X' := Diffie-Hellman share

Note over Source, Server: 7. Source fetches message IDs
Source ->> Server: request messages
loop forall n  messages:
Server ->> Source: Q'0...n := public keys<br>cid'0...n := encrypted message IDs
end

Note over Source, Server: 10. Source fetches and decrypts a message
Source ->> Server: id' := decrypted message ID
Server ->> Source: C'<br>X'
end

deactivate Source
deactivate Journalist
deactivate Server
```

-->

## Keys <!-- as of cf81f37 -->

Throughout this document, keys are notated as $component_{owner}^{scheme}$, where:

- $`component \in \{sk, pk, vk\}`$ for private ($sk$) or public ($pk$ or $vk$) components
- $`owner \in \{FPF, NR, J, S\}`$ for FPF, newsroom $NR$, journalist $J$, or source $S$; and
- $`scheme \in \{fetch, sig, APKE, PKE\}`$ for:
  - $fetch$ fetching
  - $sig$ signature
  - $APKE = \text{SD-APKE}$ ($APKE_E$ if one-time)
  - $PKE = \text{SD-PKE}$ ($PKE_E$ if one-time)

| Owner      | Private Key        | Public Key         | Usage   | Purpose  | Direction         | Lifetime      | Algorithm                    | Signed by          |
| ---------- | ------------------ | ------------------ | ------- | -------- | ----------------- | ------------- | ---------------------------- | ------------------ |
| FPF        | $`sk_{FPF}^{sig}`$ | $`vk_{FPF}^{sig}`$ |         | Signing  |                   | Long-term     | ?                            |                    |
| Newsroom   | $`sk_{NR}^{sig}`$  | $`vk_{NR}^{sig}`$  |         | Signing  |                   | Long-term     | ?                            | $`sk_{FPF}^{sig}`$ |
| Journalist | $`sk_J^{sig}`$     | $`vk_J^{sig}`$     |         | Signing  |                   | Long-term     | ?                            | $`sk_{NR}^{sig}`$  |
| Journalist | $`sk_J^{AKEM}`$    | $`pk_J^{AKEM}`$    | SD-APKE | Message  | Outgoing          | Long-term     | DH-AKEM(X25519, HKDF-SHA256) | $`sk_J^{sig}`$     |
| Journalist | $`sk_J^{fetch}`$   | $`pk_J^{fetch}`$   |         | Fetching |                   | **TBD**[^6]   | ristretto255 (Curve25519)    | $`sk_J^{sig}`$     |
| Journalist | $`sk_J^{PQ_E}`$    | $`pk_J^{PQ_E}`$    | SD-APKE | Message  | Incoming          | One-time      | ML-KEM-768                   | $`sk_J^{sig}`$     |
| Journalist | $`sk_J^{AKEM_E}`$  | $`pk_J^{AKEM_E}`$  | SD-APKE | Message  | Incoming          | One-time      | DH-AKEM(X25519, HKDF-SHA256) | $`sk_J^{sig}`$     |
| Journalist | $`sk_J^{PKE_E}`$   | $`pk_J^{PKE_E}`$   | SD-PKE  | Metadata | Incoming          | One-time      | X-Wing (X25519, ML-KEM-768)  | $`sk_J^{sig}`$     |
| Source     | $`sk_S^{fetch}`$   | $`pk_S^{fetch}`$   |         | Fetching |                   | Permanent[^7] | ristretto255 (Curve25519)    |                    |
| Source     | $`sk_S^{PQ}`$      | $`pk_S^{PQ}`$      | SD-APKE | Message  | Incoming          | Permanent[^7] | ML-KEM-768                   |                    |
| Source     | $`sk_S^{AKEM}`$    | $`pk_S^{AKEM}`$    | SD-APKE | Message  | Incoming+Outgoing | Permanent[^7] | DH-AKEM(X25519, HKDF-SHA256) |                    |
| Source     | $`sk_S^{PKE}`$     | $`pk_S^{PKE}`$     | SD-PKE  | Metadata | Incoming          | Permanent[^7] | X-Wing (X25519, ML-KEM-768)  |                    |

[^6]: **TODO:** https://github.com/freedomofpress/securedrop-protocol/blob/a0252a8ee7a6e4051c65e4e0c06b63d6ce921110/docs/wip-protocol-0.3.md?plain=1#L87

## Building blocks[^9] <!-- Section 4 as of cf81f37 -->

| Scheme          | Function                                                  | Use                                                                                                             |
| --------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
|                 | $`k \gets \text{KDF}(ik, params)`$                        | Derive a key from input key $ik$ and $params$                                                                   |
|                 | $`k \gets \text{PBKDF}(pw)`$                              | Derive a key from password $pw$ (including any parameters)                                                      |
| $`\text{SIG}`$  | Signature scheme                                          |                                                                                                                 |
|                 | $`(sk, vk) \gets^{\$} \text{KGen}()`$                     | Generate keys                                                                                                   |
|                 | $`\sigma \gets^{\$} \text{Sign}(sk, m)`$                  | Sign a message $m$ using a signing key $sk$                                                                     |
|                 | $`b \in \{0, 1\} \gets \text{Vfy}(vk, m, \sigma)`$        | Verify signature $\sigma$ over a message $m$ using a verifying key $vk$                                         |
| $`\text{AEAD}`$ | Nonce-based authenticated encryption with associated data |                                                                                                                 |
|                 | $`c \gets \text{Enc}(k, nonce, ad, m)`$                   | Encrypt a message $m$ using a key $k$, a nonce $nonce$, and associated data $ad$                                |
|                 | $`m \gets \text{Dec}(k, nonce, ad, c)`$                   | Decrypt a ciphertext $c$; rest as above                                                                         |
| $`\text{PKE}`$  | Public-key encryption                                     |                                                                                                                 |
|                 | $`(sk, pk) \gets^{\$} \text{KGen}()`$                     | Generate keys                                                                                                   |
|                 | $`c \gets^{\$} \text{Enc}(pk, m, ad, info)`$              | Encrypt a message $m$ to a recipient's public key $pk$, associated data $ad$, and $info$                        |
|                 | $`m \gets \text{Dec}(sk, c, ad, info)`$                   | Decrypt a ciphertext $c$ using a recipient's private key $sk$; rest as above                                    |
| $`\text{APKE}`$ | Authenticated public-key encryption                       |                                                                                                                 |
|                 | $`(sk, pk) \gets^{\$} \text{KGen}()`$                     | Generate keys                                                                                                   |
|                 | $`c \gets^{\$} \text{AuthEnc}(sk, pk, m, ad, info)`$      | Encrypt a message $m$ to a recipient's public key $pk$ using private key $sk$, associated data $ad$, and $info$ |
|                 | $`m \gets \text{AuthDec}(sk, pk, c, ad, info)`$           | Decrypt a ciphertext $c$ using a recipient's private key $sk$ and a sender's public key $pk$; rest as above     |

The protocol composes two modes of [Hybrid Public-Key Encryption (RFC 9180)][RFC 9180]:

- For metadata protection, `SD-PKE` is an instantiation of [HPKE `Base`
  mode][RFC 9180 §5.1.1].
- For message encryption, `SD-APKE` wraps HPKE `AuthPSK` mode, following listing
  17 of Alwen et al. (2023), ["The Pre-Shared Key Modes of HPKE"][alwen2023].

### Metadata protection via `SD-PKE`: SecureDrop PKE <!-- Figure 8 as of cf81f37 -->

$\text{SD-PKE}[\text{KEM}_H, \text{AEAD}, \text{KS}]$ instantiates [HPKE `Base`
mode][RFC 9180 §5.1.1] with:

- $\text{KEM}_H =$ X-Wing
- $\text{AEAD} =$ AES-GCM
- $\text{KS} =$ HPKE's [`KeySchedule()`][RFC 9180 §5.1] with [HKDF-SHA256][RFC 9180 §7.2]

| Syntax                                                | Description                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------ |
| $`(sk_S^{PKE}, pk_S^{PKE}) \gets^{\$} \text{KGen}()`$ | Generate keys                                                |
| $`(c, c') \gets^{\$} \text{Enc}(pk_R^{PKE}, m)`$      | Encrypt a message $m$ via HPKE in [`mode_base`][RFC 9180 §5] |
| $`m \gets \text{Dec}(sk_R^{PKE}, (c, c'))`$           | Decrypt a message $m$ via HPKE in [`mode_base`][RFC 9180 §5] |

Concretely, using HPKE's [single-shot APIs][RFC 9180 §6.1]:

```python
def KGen():
    (skS, pkS) = KEM_H.KGen()
    return (skS, pkS)

def Enc(pkR, m):
    c, cp = HPKE.SealBase(pkR=pkR, info=None, aad=None, pt=m)  # cp = c'
    return (c, cp)

# cp = c' in (c, cp)
def Dec(skR, c, cp):
    m = HPKE.OpenBase(enc=c, skR=skR, info=None, aad=None, ct=cp)
    return m
```

### Message encryption

#### `AKEM`: Authenticated KEM <!-- Definition A.7 as of cf81f37 -->

$\text{AKEM}$ instantiates the [DH-based KEM][RFC 9180 §4.1]
$\text{DHKEM}(\text{Group}, \text{KDF})$ with:

- $\text{Group} =$ [X25519][RFC 9180 §7.1]
- $\text{KDF} =$ [HKDF-SHA256][RFC 9180 §7.1]

| Syntax                                                           | Description                                                                                                                                                              |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| $`(sk_S^{AKEM}, pk_S^{AKEM}) \gets^{\$} \text{KGen}()`$          | Generate keys; for DH-AKEM, $(sk, pk) = (x, \text{DH}(g, x)) = (x, g^x)$                                                                                                 |
| $`(c, K) \gets^{\$} \text{AuthEncap}(sk_S^{AKEM}, pk_R^{AKEM})`$ | Encapsulate a ciphertext $c$ and a shared secret $K$ using a sender's private key $sk_S$ and a receiver's public key $pk_R$; for DH-AKEM, $(c, K) = (pkE, K) = (g^x, K)$ |
| $`K \gets \text{AuthDecap}(sk_R^{AKEM}, pk_S^{AKEM}, c)`$        | Decapsulate a shared secret $K$ using a receiver's private key $sk_R$, a sender's public key $pk_S$, and a ciphertext $c$; for DH-AKEM, $c = pkE$                        |

Concretely, these functions are used as specified in [RFC 9180 §4.1].

#### `pskAPKE`: Pre-shared-key authenticated PKE <!-- Figure 6 as of cf81f37 -->

$\text{pskAPKE}[\text{AKEM}, \text{KS}, \text{AEAD}]$ instantiates [HPKE
`AuthPSK` mode][RFC 9180 §5.1.4] with:

- $\text{AKEM}$ as above
- $\text{KS} =$ HPKE's [`KeySchedule()`][RFC 9180 §5.1] with [HKDF-SHA256][RFC 9180 §7.2]
- $\text{AEAD} =$ AES-GCM

| Syntax                                                                              | Description                                                                                           |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| $`(c_1, c') \gets^{\$} \text{pskAEnc}(sk_S^{AKEM}, pk_R^{AKEM}, psk, m, ad, info)`$ | Encrypt a message $m$ with associated data $ad$ and $info$ via HPKE in [`mode_auth_psk`][RFC 9180 §5] |
| $`m \gets \text{pskADec}(pk_S^{AKEM}, sk_R^{AKEM}, psk, (c_1, c'), ad, info)`$      | Decrypt a message $m$ with associated data $ad$ and $info$ via HPKE in [`mode_auth_psk`][RFC 9180 §5] |

Concretely, using HPKE's [single-shot APIs][RFC 9180 §6.1]:

```python
PSK_ID = "SD-pskAPKE"

def pskAEnc(skS, pkR, psk, m, ad, info):
    c1, cp = HPKE.SealAuthPSK(pkR=pkR, info=info, aad=ad, pt=m, psk=psk, psk_id=PSK_ID, skS=skS)  # cp = c'
    return (c1, cp)

# cp = c' in (c1, cp)
def pskADec(pkS, skR, psk, c1, cp, ad, info):
    m = HPKE.OpenAuthPSK(enc=c1, skR=skR, info=info, aad=ad, ct=cp, psk=psk, psk_id=PSK_ID, pkS=pkS)
    return m
```

#### `SD-APKE`: SecureDrop APKE <!-- Figure 7 as of cf81f37 -->

$\text{SD-APKE}[\text{AKEM}, \text{KEM}_{PQ}, \text{AEAD}]$ is constructed with:

- $\text{AKEM}$ as above
- $\text{KEM}_{PQ} =$ ML-KEM-768
- $\text{pskAPKE}$ as above

| Syntax                                                                                                                                      | Description                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| $`(sk_S^{APKE}, pk_S^{APKE}) \gets^{\$} \text{KGen}()`$                                                                                     | Generate keys                                              |
| $`((c_1, c'), c_2) \gets^{\$} \text{AuthEnc}(sk_S^{APKE} = (sk_S^{AKEM}, sk_S^{PQ}), pk_R^{APKE} = (pk_R^{AKEM}, pk_R^{PQ}), m, ad, info)`$ | Encrypt a message $m$ with associated data $ad$ and $info$ |
| $`m \gets \text{AuthDec}(sk_R^{APKE} = (sk_R^{AKEM}, sk_R^{PQ}), pk_S^{APKE} = (pk_S^{AKEM}, pk_S^{PQ}), ((c_1, c'), c_2), ad, info)`$      | Decrypt a message $m$ with associated data $ad$ and $info$ |

Concretely:

```python
def KGen():
    (sk1, pk1) = AKEM.KGen()
    (sk2, pk2) = KEM_PQ.KGen()
    sk = (sk1, sk2)
    pk = (pk1, pk2)
    return (sk, pk)

def AuthEnc(
        sk=(skS1, skS2),
        pk=(pkR1, pkR2),
        m, ad, info):
    (c2, K2) = KEM_PQ.Encap(pkR=pkR2)
    (c1, cp) = pskAEnc(skS=skS1, pkR=pkR1, psk=K2, m=m, ad=ad, info=c2 + info)  # cp = c'
    return ((c1, cp), c2)

def AuthDec(
        sk=(skR1, skR2),
        pk=(pkS1, pkS2),
        c1, cp, c2,  # cp = c' in ((c1, cp), c2)
        ad, info):
    K2 = KEM_PQ.Decap(skR=skR2, enc=c2)
    m = pskADec(pkS=pkS1, skR=skR1, psk=K2, c1=c1, cp=cp, ad=ad, info=c2 + info)
    return m
```

## Setup

### 1. FPF

| FPF                                                          |
| ------------------------------------------------------------ |
| $`(sk_{FPF}^{sig}, vk_{FPF}^{sig}) \gets^{\$} \text{Gen}()`$ |

The server, the journalist client, and the source client SHOULD be built with
FPF's signing key $vk_{FPF}^{sig}$ pinned.[^2]

### 2. Newsroom

| Newsroom                                                   |                                   | FPF                                                                    |
| ---------------------------------------------------------- | --------------------------------- | ---------------------------------------------------------------------- |
| $`(sk_{NR}^{sig}, vk_{NR}^{sig}) \gets^{\$} \text{Gen}()`$ |                                   |                                                                        |
|                                                            | $`\longrightarrow vk_{NR}^{sig}`$ | Verify manually                                                        |
|                                                            |                                   | $`\sigma_{FPF} \gets^{\$} \text{Sign}(sk_{FPF}^{sig}, vk_{NR}^{sig})`$ |
|                                                            | $`\sigma_{FPF} \longleftarrow`$   |

The server MUST be deployed with the newsroom's verifying key $vk_{NR}^{sig}$
pinned. The server MAY be deployed with FPF's verifying key $vk_{FPF}^{sig}$
pinned.[^2]

### 3. Journalist

#### 3.1. Enrollment

| Journalist                                                                   |                                                           | Newsroom                                                          |
| ---------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| $`(sk_J^{sig}, vk_J^{sig}) \gets^{\$} \text{Gen}()`$                         |                                                           |                                                                   |
|                                                                              | $`\longrightarrow vk_J^{sig}`$                            | Verify $vk_J^{sig}$ manually, then store for $J$                  |
|                                                                              |                                                           | $`\sigma_{NR} \gets^{\$} \text{Sign}(sk_{NR}^{sig}, vk_J^{sig})`$ |
|                                                                              |                                                           | Store $\sigma_{NR}$ for $J$                                       |
| $`(sk_J^{AKEM}, pk_J^{AKEM}) \gets^{\$} \text{AKEM.KGen}()`$                 |                                                           |                                                                   |
| $`(sk_J^{fetch}, pk_J^{fetch}) \gets^{\$} \text{KGen}()`$ (**TODO**)         |                                                           |                                                                   |
| $`\sigma_J \gets^{\$} \text{Sign}(sk_J^{sig}, (pk_J^{AKEM}, pk_J^{fetch}))`$ |                                                           |                                                                   |
|                                                                              | $`\longrightarrow (\sigma_J, pk_J^{AKEM}, pk_J^{fetch})`$ |                                                                   |
|                                                                              |                                                           | $`\text{Vfy}(vk_J^{sig}, (pk_J^{AKEM}, pk_J^{fetch}), \sigma_J)`$ |
|                                                                              |                                                           | Store $(\sigma_J, pk_J^{AKEM}, pk_J^{fetch})$ for $J$             |

#### 3.2. Setup and periodic replenishment of $n$ ephemeral keybundles

Each journalist $J$ MUST generate and maintain a pool of $n$ ephemeral
keybundles. For each keybundle:

| Journalist                                                                     |                                                             | Server                                                              |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------- |
| $`(sk_J^{APKE_E}, pk_J^{APKE_E}) \gets^{\$} \text{SD-APKE.KGen}()`$            |                                                             |                                                                     |
| $`(sk_J^{PKE_E}, pk_J^{PKE_E} \gets^{\$} \text{SD-PKE.KGen}()`$                |                                                             |                                                                     |
| $`\sigma_J \gets^{\$} \text{Sign}(sk_J^{sig}, (pk_J^{APKE_E}, pk_J^{PKE_E}))`$ |                                                             |                                                                     |
|                                                                                | $`\longrightarrow (\sigma_J, pk_J^{APKE_E}, pk_J^{PKE_E})`$ |
|                                                                                |                                                             | $`\text{Vfy}(vk_J^{sig}, (pk_J^{APKE_E}, pk_J^{PKE_E}), \sigma^J)`$ |
|                                                                                |                                                             | Store $(\sigma_J, pk_J^{APKE_E}, pk_J^{PKE_E})$ for $J$             |

### 4. Source

To begin each session, a source MUST enter (on their first visit) or reenter (on
a subsequent visit) some $passphrase$:

| Source                                                                                           |
| ------------------------------------------------------------------------------------------------ |
| $`sk_S^{fetch} \Vert sk_S^{PQ} \Vert sk_S^{AKEM} \Vert sk_S^{PKE} \gets \text{KDF}(passphrase)`$ |

## Messaging protocol

SecureDrop is a first-contact protocol between an unknown party (an anonymous
source) and well-known parties (journalists).

The preceding setup steps are _role-specific_: sources' and journalists' setup
steps are different. By contrast, the following protocol steps are
_role-agnostic_ and _turn-specific_. Except where otherwise noted, sources and
journalists execute the same fetching step (5), sending step (6), and receiving
step (7), in any order.

Only a source can initiate a conversation. In other words, a source is always
the first sender.

### 5. Sender fetches keys and verifies their authenticity <!-- Figure 1 as of 7944378 -->

A sender knows their own keys and the newsroom's signing key $vk_{NR}^{sig}$. In
addition, in the **reply case,** if the sender is a journalist replying to a
source, they also already know their recipient's keys without further
verification.

| Anyone          | All senders     | Reply case      |
| --------------- | --------------- | --------------- |
| $vk_{NR}^{sig}$ | $vk_{NR}^{sig}$ | $vk_{NR}^{sig}$ |
|                 | $pk_S^{APKE}$   | $pk_R^{APKE}$   |
|                 | $pk_S^{PKE}$    | $pk_R^{PKE}$    |
|                 | $pk_S^{fetch}$  | $pk_R^{fetch}$  |
|                 | $sk_S^{APKE}$   |
|                 | $sk_S^{PKE}$    |
|                 | $sk_S^{fetch}$  |

For some newsroom $NR$ and all its enrolled journalists $J_i$:

| Sender                                                                                                               |                                 | Server                                                                                        |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------- |
|                                                                                                                      | $\longrightarrow$ `RequestKeys` |                                                                                               |
|                                                                                                                      |                                 | $`pks = \{(vk_{R,i}^{sig}, pk_{R,i}^{APKE}, pk_{R,i}^{PKE}, pk_{R,i}^{fetch})\}`$ for all $i$ |
|                                                                                                                      |                                 | $`sigs = \{(\sigma_{R,i}, \sigma_{NR,i})\}`$ for all $i$                                      |
|                                                                                                                      | $`(pks, sigs) \longleftarrow`$  |                                                                                               |
| $`\forall i:`$                                                                                                       |                                 |                                                                                               |
| $`\text{Vfy}(vk_{NR}^{sig}, pk_{R,i}^{sig}, \sigma_{NR,i})`$                                                         |                                 |                                                                                               |
| $`\text{Vfy}(vk_{R,i}^{sig}, (pk_{R,i}^{APKE}, pk_{R,i}^{PKE}, pk_{R,i}^{fetch}), \sigma_{R,i})`$                    |                                 |                                                                                               |
|                                                                                                                      |                                 |                                                                                               |
| **Reply case:** The journalist replaces their own keys with those of the source to whom they are replying:           |                                 |                                                                                               |
| $`pks \gets pks \setminus \{pk_S^{APKE}, pk_S^{PKE}, pk_S^{fetch}\} \cup \{pk_R^{APKE}, pk_R^{PKE}, pk_R^{fetch}\}`$ |                                 |                                                                                               |

### 6. Sender submits a message <!-- Figure 1 as of 7944378 -->

Then, for some message $m$, for all keys $(pk_{R,i}^{APKE}, pk_{R,i}^{PKE},
pk_{R,i}^{fetch}) \in pks$:

| Source                                                                              |                                 | Server                                         |
| ----------------------------------------------------------------------------------- | ------------------------------- | ---------------------------------------------- |
| $`pt \gets m \Vert pk_S^{fetch} \Vert pk_S^{PKE} `$                                 |                                 |                                                |
| $`ct^{APKE} \gets \text{SD-APKE.AuthEnc}(sk_S^{APKE}, pk_{R,i}^{APKE}, pt, NR, -)`$ |                                 |                                                |
| $`ct^{PKE} \gets \text{SD-PKE.Enc}(pk_{R,i}^{PKE}, pk_S^{APKE}, -, -)`$             |                                 |                                                |
| $`C_S \gets (ct^{APKE}, ct^{PKE})`$                                                 |                                 |                                                |
| $`x \gets^{\$} \mathcal{E}_H`$[^8]                                                  |                                 |                                                |
| $`X \gets g^x`$                                                                     |                                 |                                                |
| $`Z \gets (pk_{R,i}^{fetch})^x`$                                                    |                                 |                                                |
|                                                                                     | $`\longrightarrow (C_S, X, Z)`$ |                                                |
|                                                                                     |                                 | $`id \gets^{\$} \{0,1\}^{il}`$ for length $il$ |
|                                                                                     |                                 | Store $(id, C_S, X, Z)$                        |

### 7. Receiver fetches and decrypts messages <!-- Figure 2 as of 7944378 -->

A receiver knows their own keys and the newsroom's $vk_{NR}^{sig}$:

| Anyone          | All receivers   |
| --------------- | --------------- |
| $vk_{NR}^{sig}$ | $vk_{NR}^{sig}$ |
|                 | $pk_R^{APKE}$   |
|                 | $pk_R^{PKE}$    |
|                 | $pk_R^{fetch}$  |
|                 | $sk_R^{APKE}$   |
|                 | $sk_R^{PKE}$    |
|                 | $sk_R^{fetch}$  |

For some newsroom $NR$:

| Server                                                                                |                                                | Receiver                                                                        |
| ------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------- |
|                                                                                       |                                                | $`fetched \gets \emptyset`$                                                     |
|                                                                                       | $\longleftarrow$ `RequestMessages`             |                                                                                 |
| $`\forall C_i = (id_i, C_{S_i}, X_i, Z_i):`$ **TODO:** pad up to $n$ total challenges |                                                |                                                                                 |
| $`r_i \gets^{\$} \mathcal{E}_H`$[^8]                                                  |                                                |                                                                                 |
| $`nonce_i \gets 0^{nl}`$ for length $nl$                                              |                                                |                                                                                 |
| $`idk_i \gets \text{KDF}(Z_i^{r_i}, NR)`$                                             |                                                |                                                                                 |
| $`eid_i \gets \text{AEAD.Enc}(idk_i, nonce_i, -, id_i)`$                              |                                                |                                                                                 |
| $`Q_i \gets X_i^{r_i}`$                                                               |                                                |                                                                                 |
|                                                                                       | $`\longrightarrow \forall i: \{(eid_i, Q_i\}`$ |                                                                                 |
|                                                                                       |                                                | $`cids = \emptyset`$                                                            |
|                                                                                       |                                                | $`\forall i:`$                                                                  |
|                                                                                       |                                                | $`tk_i \gets \text{KDF}(Q_i^{sk_R^{fetch}}, NR)`$                               |
|                                                                                       |                                                | $`nonce_i \gets 0^{nl}`$ for length $nl$                                        |
|                                                                                       |                                                | $`res_i \gets \text{AEAD.Dec}(tk_i, nonce_i, -, eid_i)`$                        |
|                                                                                       |                                                | If $res_i \neq \bot$: $`cids \gets cids \cup \{res_i\}`$                        |
|                                                                                       |                                                | $`tofetch = fetched \setminus cids`$                                            |
|                                                                                       |                                                | If $tofetch \neq \emptyset$: $`cid \gets tofetch[0]`$                           |
|                                                                                       | $`cid \longleftarrow`$                         |                                                                                 |
|                                                                                       | $`\longrightarrow C_{S_i}`$ where $id_i = cid$ |                                                                                 |
|                                                                                       |                                                | $`(ct^{APKE}, ct^{PKE}) \gets C_{S_i}`$                                         |
|                                                                                       |                                                | $`pk_S^{APKE} \gets \text{SD-PKE.Dec}(sk_R^{PKE}, ct^{PKE}, -, -)`$             |
|                                                                                       |                                                | $`pt \gets \text{SD-APKE.AuthDec}(sk_R^{APKE}, pk_S^{APKE}, ct^{APKE}, NR, -)`$ |
|                                                                                       |                                                | $`m \Vert pk_S^{fetch} \Vert pk_S^{PKE} \gets pt`$                              |
|                                                                                       |                                                | $`fetched \gets fetched \cup \{cid\}`$                                          |
|                                                                                       |                                                | If $tofetch \setminus \{cid\} \neq \emptyset$: repeat from `RequestMessages`    |

[^1]: Currently configured as [`CHUNK`][chunk].

[^2]: See [`draft-pki.md`](./draft-pki.md) for further considerations.

[^3]: Adapted from Maier §5.4.1.

<!--
[^6]: TODO kept inline above.
-->

[^7]:
    The source's keys are considered "permanent" because they are derived
    deterministically from the source's passphrase, which cannot be changed.

[^8]:
    $\mathcal{E}_H \subset \mathbb{Z}$ per Definition 4 of Alwen et al.
    (2020), ["Analyzing the HPKE Standard"][alwen2020].

[^9]:
    In the listings that follow, mathematical syntax uses `-` for the empty
    string, while Python pseudocode uses `None`.

[alwen2020]: https://eprint.iacr.org/2020/1499
[alwen2023]: https://eprint.iacr.org/2023/1480
[chunk]: https://github.com/freedomofpress/securedrop-protocol/blob/664f8c66312b45e00d1e2b4a26bc466ff105c3ca/README.md?plain=1#L105
[RFC 2119]: https://datatracker.ietf.org/doc/html/rfc2119
[RFC 9180]: https://datatracker.ietf.org/doc/html/rfc9180
[RFC 9180 §4.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem
[RFC 9180 §5]: https://datatracker.ietf.org/doc/html/rfc9180#name-hybrid-public-key-encryptio
[RFC 9180 §5.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-creating-the-encryption-con
[RFC 9180 §5.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-encryption-to-a-public-key
[RFC 9180 §5.1.4]: https://datatracker.ietf.org/doc/html/rfc9180#name-authentication-using-both-a
[RFC 9180 §6.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-6.1
[RFC 9180 §7.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-key-encapsulation-mechanism
[RFC 9180 §7.2]: https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd
