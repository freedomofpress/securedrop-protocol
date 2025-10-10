# SecureDrop Protocol specification

| Version |
| ------- |
| 0.3     |

> [!NOTE]
> The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
> RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
> described in [RFC 2119].

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

## Keys

In the table below:

> For keys, we use the notation $X_{A,B}$, where $X$ represents the key owner
> ($`X \in \{NR, J, S\}`$ [for newsroom, journalist, and source, respectively]),
> $A$ represents the key's usage ($`A \in \{sig,fetch,pke,pq,md\}`$), and is prefixed
> with an "e" if the key is a one-time key. $B$ indicates whether the component is
> private or public. For Diffie-Hellman keys $x$, the public component is
> represented by the exponentiation $DH(g, x)$.[^3]

| Owner      | Secret Key       | Pubkey           | Usage   | Purpose  | Direction         | Lifetime      | Algorithm                    | Signed by          |
| ---------- | ---------------- | ---------------- | ------- | -------- | ----------------- | ------------- | ---------------------------- | ------------------ |
| FPF        | $`FPF_{sig,sk}`$ | $`FPF_{sig,pk}`$ |         | Signing  |                   | Long-term     | ?                            |                    |
| Newsroom   | $`NR_{sig,sk}`$  | $`NR_{sig,pk}`$  |         | Signing  |                   | Long-term     | ?                            | $`FPF_{sig,sk}`$   |
| Journalist | $`J_{sig,sk}`$   | $`J_{sig,pk}`$   |         | Signing  |                   | Long-term     | ?                            | $`NR_{sig,sk}`$    |
| Journalist | $`J_{apke,sk}`$  | $`J_{apke,pk}`$  | SD-APKE | Message  | Outgoing          | Long-term     | DH-AKEM(X25519, HKDF-SHA256) | $`J_{sig,sk}`$     |
| Journalist | $`J_{fetch,sk}`$ | $`J_{fetch,pk}`$ |         | Fetching |                   | **TBD**[^6]   | ristretto255 (Curve25519)    | $`J_{sig,sk}`$[^4] |
| Journalist | $`J_{epq,sk}`$   | $`J_{epq,pk}`$   | SD-APKE | Message  | Incoming          | One-time      | ML-KEM-768                   | $`J_{sig,sk}`$     |
| Journalist | $`J_{epke,sk}`$  | $`J_{epke,pk}`$  | SD-APKE | Message  | Incoming          | One-time      | DH-AKEM(X25519, HKDF-SHA256) | $`J_{sig,sk}`$     |
| Journalist | $`J_{emd,sk}`$   | $`J_{emd,pk}`$   | SD-PKE  | Metadata | Incoming          | One-time      | X-Wing (X25519, ML-KEM-768)  | $`J_{sig,sk}`$     |
| Source     | $`S_{fetch,sk}`$ | $`S_{fetch,pk}`$ |         | Fetching |                   | Permanent[^7] | ristretto255 (Curve25519)    |                    |
| Source     | $`S_{pq,sk}`$    | $`S_{pq,pk}`$    | SD-APKE | Message  | Incoming          | Permanent[^7] | ML-KEM-768                   |                    |
| Source     | $`S_{pke,sk}`$   | $`S_{pke,pk}`$   | SD-APKE | Message  | Incoming+Outgoing | Permanent[^7] | DH-AKEM(X25519, HKDF-SHA256) |                    |
| Source     | $`S_{md,sk}`$    | $`S_{md,pk}`$    | SD-PKE  | Metadata | Incoming          | Permanent[^7] | X-Wing (X25519, ML-KEM-768)  |                    |

[^4]: **TODO:** Discussion of whether the newsroom's or the journalist's signing key signs the journalist's fetching key.

[^6]: **TODO:** https://github.com/freedomofpress/securedrop-protocol/blob/a0252a8ee7a6e4051c65e4e0c06b63d6ce921110/docs/wip-protocol-0.3.md?plain=1#L87

## Functions and notation

**TODO:** Reevaluate this table after revising the "Setup" and "Message
Protocol" sections from the manuscript.

| Syntax                                                    | Description                                                                       |
| --------------------------------------------------------- | --------------------------------------------------------------------------------- |
| $`h \gets \text{Hash}(m)`$                                | Hash message $m$ to digest $h$                                                    |
| $`k \Vert k_1 \Vert \dots \Vert k_n \gets \text{KDF}(m)`$ | Derive one or more keys $k$ from a message $m$                                    |
| $`\sigma \gets^{\$} \text{Sign}(sk_S, m)`$                | Sign a message $m$ with the sender's private key $sk_S$                           |
| $`b \in \{0,1\} \gets \text{Vfy}(pk_S, m, \sigma)`$       | Verify a message $m$ and a signature $\sigma$ with the sender's public key $pk_S$ |
| $` g^x \gets \text{DH(g, x)}`$                            | Diffie-Hellman exponentiation of private component $x$                            |
| $`r \gets^{\$} \text{Rand}()`$                            | Generate a random value                                                           |
| $`mp \gets \text{Pad}(m)`$                                | Pad a message $m$ to a constant size[^1]                                          |
| $`-`$                                                     | The empty string (or `None` in pseudocode)                                        |

## Cryptographic APIs

The protocol composes two modes of [Hybrid Public-Key Encryption (RFC 9180)][RFC 9180]:

- For metadata protection, `SD-PKE` is an instantiation of [HPKE `Base`
  mode][RFC 9180 §5.1.1].
- For message encryption, `SD-APKE` wraps HPKE `AuthPSK` mode, following listing
  17 of Alwen et al. (2023), ["The Pre-Shared Key Modes of HPKE"][alwen2023].

### Metadata protection via `SD-PKE`: SecureDrop PKE <!-- Figure 4 as of 7944378 -->

$\text{SD-PKE}[\text{KEM}_H, \text{AEAD}, \text{KS}]$ instantiates [HPKE `Base`
mode][RFC 9180 §5.1.1] with:

- $\text{KEM}_H =$ X-Wing
- $\text{AEAD} =$ AES-GCM
- $\text{KS} =$ HPKE's [`KeySchedule()`][RFC 9180 §5.1] with [HKDF-SHA256][RFC 9180 §7.2]

| Syntax                                     | Description                                                  |
| ------------------------------------------ | ------------------------------------------------------------ |
| $`(sk, pk) \gets^{\$} \text{KGen}()`$      | Generate keys                                                |
| $`(c, c') \gets^{\$} \text{Enc}(pk_R, m)`$ | Encrypt a message $m$ via HPKE in [`mode_base`][RFC 9180 §5] |
| $`m \gets \text{Dec}(sk_R, (c, c'))`$      | Decrypt a message $m$ via HPKE in [`mode_base`][RFC 9180 §5] |

Concretely:

```python
def KGen():
    (sk, pk) = KEM_H.KGen()
    return (sk, pk)

def Enc(pkR, m):
    (c, K3) = KEM_H.Encap(pkR)
    (k, nonce) = KS(K3, None, None)
    cp = AEAD.Enc(k, nonce, None, m)  # cp = c'
    return (c, cp)

def Dec(skR, (c, cp)):  # cp = c'
    K3 = KEM_H.Decap(skR, c)
    (k, nonce) = KS(K3, None, None)
    m = AEAD.Dec(k, nonce, None, cp)
    return m
```

### Message encryption

#### `AKEM`: Authenticated KEM <!-- Definition 4.1 as of 7944378 -->

$\text{AKEM}$ instantiates the [DH-based KEM][RFC 9180 §4.1]
$\text{DHKEM}(\text{Group}, \text{KDF})$ with:

- $\text{Group} =$ [X25519][RFC 9180 §7.1]
- $\text{KDF} =$ [HKDF-SHA256][RFC 9180 §7.1]

| Syntax                                             | Description                                                                                                                                                              |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| $`(sk_S, pk_S) \gets^{\$} \text{KGen}()`$          | Generate keys; for DH-AKEM, $(sk, pk) = (x, \text{DH}(g, x)) = (x, g^x)$                                                                                                 |
| $`(c, K) \gets^{\$} \text{AuthEncap}(sk_S, pk_R)`$ | Encapsulate a ciphertext $c$ and a shared secret $K$ using a sender's private key $sk_S$ and a receiver's public key $pk_R$; for DH-AKEM, $(c, K) = (pkE, K) = (g^x, K)$ |
| $`K \gets \text{AuthDecap}(sk_R, pk_S, c)`$        | Decapsulate a shared secret $K$ using a receiver's private key $sk_R$, a sender's public key $pk_S$, and a ciphertext $c$; for DH-AKEM, $c = pkE$                        |

Concretely, these functions are used as specified in [RFC 9180 §4.1].

#### `pskAPKE`: Pre-shared-key authenticated PKE <!-- Figure 5 as of 7944378 -->

$\text{pskAPKE}[\text{AKEM}, \text{KS}, \text{AEAD}]$ instantiates [HPKE
`AuthPSK` mode][RFC 9180 §5.1.4] with:

- $\text{AKEM}$ as above
- $\text{KS} =$ HPKE's [`KeySchedule()`][RFC 9180 §5.1] with [HKDF-SHA256][RFC 9180 §7.2]
- $\text{AEAD} =$ AES-GCM

| Syntax                                                                | Description                                                                                                                   |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| $`(c_1, c') \gets^{\$} \text{pskAEnc}(sk_S, pk_R, psk, m, ad, info)`$ | Encrypt a message $m$ with associated data $ad$ and $info$ via HPKE in [`mode_auth_psk`][RFC 9180 §5]                         |
| $`m \gets \text{pskADec}(pk_S, sk_R, psk, (c_1, c'), ad, info)`$      | Decrypt a message $m$ with associated data $ad$ and $info$ via HPKE in [`mode_auth_psk`][RFC 9180 §5] <!-- FIXME: 28dd67c --> |

Concretely:

```python
def pskAEnc(skS, pkR, psk, m, ad, info):
    (c1, K1) = AKEM.AuthEncap(skS, pkR)
    (k, nonce) = KS(K1, psk, info)
    cp = AEAD.Enc(k, nonce, ad, m)  # cp = c'
    return (c1, cp)

# FIXME: 28dd67c
def pskADec(pkS, skR, psk, (c1, cp), ad, info):  # cp = c'
    K1 = AKEM.AuthDecap(skR, pkS, c1)
    (k, nonce) = KS(K1, psk, info)
    m = AEAD.Dec(k, nonce, ad, cp)
    return m
```

#### `SD-APKE`: SecureDrop APKE <!-- Figure 3 as of 7944378 -->

$\text{SD-APKE}[\text{AKEM}, \text{KEM}_{PQ}, \text{AEAD}]$ is constructed with:

- $\text{AKEM}$ as above
- $\text{KEM}_{PQ} =$ ML-KEM-768
- $\text{pskAPKE}$ as above

| Syntax                                                                                                        | Description                                                |
| ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| $`(sk, pk) \gets^{\$} \text{KGen}()`$                                                                         | Generate keys                                              |
| $`((c_1, c'), c_2) \gets^{\$} \text{AuthEnc}(sk_S = (sk_S^1, sk_S^2), pk_S = (pk_R^1, pk_R^2), m, ad, info)`$ | Encrypt a message $m$ with associated data $ad$ and $info$ |
| $`m \gets \text{AuthDec}(sk_R = (sk_R^1, sk_R^2), pk_S = (pk_S^1, pk_S^2), ((c_1, c'), c_2), ad, info)`$      | Decrypt a message $m$ with associated data $ad$ and $info$ |

Concretely:

```python
def KGen():
    (sk1, pk1) = AKEM.KGen()
    (sk2, pk2) = KEM_PQ.KGen()
    sk = (sk1, sk2)
    pk = (pk1, pk2)
    return (sk, pk)

def AuthEnc((skS1, skS2), (pkR1, pkR2), m, ad, info):
    (c2, K2) = KEM_PQ.Encap(pkR2)
    (c1, cp) = pskAEnc(skS1, pkR1, K2, m, ad, c2)  # cp = c'
    return ((c1, cp), c2)

def AuthDec((skR1, skR2), (pkS1, pkS2), ((c1, cp), c2), ad, info):  # cp = c'
    K2 = KEM_PQ.Decap(skR2, c2)
    m = pskADec(pkS1, skR1, K2, (c1, cp), ad, c2)  # FIXME: 28dd67c
    return m
```

## Setup

### 1. FPF

| FPF                                                      |
| -------------------------------------------------------- |
| $`(FPF_{sig,sk}, FPF_{sig,pk}) \gets^{\$} \text{Gen}()`$ |

The server, the journalist client, and the source client SHOULD be built with
$FPF_{sig,pk}$ pinned.[^2]

### 2. Newsroom

| Newsroom                                               |                                 | FPF                                                                |
| ------------------------------------------------------ | ------------------------------- | ------------------------------------------------------------------ |
| $`(NR_{sig,sk}, NR_{sig,pk}) \gets^{\$} \text{Gen}()`$ |                                 |                                                                    |
|                                                        | $`\longrightarrow NR_{sig,pk}`$ | Verify manually                                                    |
|                                                        |                                 | $`\sigma^{FPF} \gets^{\$} \text{Sign}(FPF_{sig,sk}, NR_{sig,pk})`$ |
|                                                        | $`\sigma^{FPF} \longleftarrow`$ |

The server MUST be deployed with $NR_{sig,pk}$ pinned. The server MAY be
deployed with $\sigma^{FPF}$ pinned.[^2]

### 3. Journalist

#### 3.1. Enrollment

| Journalist                                               |                                                         | Newsroom                                                                                   |
| -------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| $`(J_{sig,sk}, J_{sig,pk}) \gets^{\$} \text{Gen}()`$     |                                                         |                                                                                            |
| $`(J_{fetch,sk}, J_{fetch,pk}) \gets^{\$} \text{Gen}()`$ |                                                         |                                                                                            |
| $`(J_{dh,sk}, J_{dh,pk}) \gets^{\$} \text{Gen}()`$       |                                                         |                                                                                            |
|                                                          | $`\longrightarrow J_{sig,pk}, J_{fetch,pk}, J_{dh,pk}`$ | Verify manually, then save for $J$                                                         |
|                                                          |                                                         | $`\sigma^{NR} \gets^{\$} \text{Sign}(NR_{sig,sk}, (J_{sig,pk}, J_{fetch,pk}, J_{dh,pk}))`$ |

#### 3.2. Setup and periodic replenishment of $n$ ephemeral keys

Each journalist $J$ MUST generate and maintain a pool of $n$ ephemeral keys.
For each key:

| Journalist                                                                              |                                                                    | Server                                                                       |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| $`(J_{edh,sk}, J_{edh,pk}) \gets^{\$} \text{Gen}()`$                                    |                                                                    |                                                                              |
| $`(J_{ekem,sk}, J_{ekem,pk}) \gets^{\$} \text{Gen}()`$                                  |                                                                    |                                                                              |
| $`(J_{epke,sk}, J_{epke,pk}) \gets^{\$} \text{Gen}()`$                                  |                                                                    |                                                                              |
| $`\sigma^J \gets^{\$} \text{Sign}(J_{sig,sk}, (J_{edh,pk}, J_{ekem,pk}, J_{epke,pk}))`$ |                                                                    |                                                                              |
|                                                                                         |                                                                    | $`\text{Vfy}(J_{sig,pk}, (J_{edh,pk}, J_{ekem,pk}, J_{epke,pk}), \sigma^J)`$ |
|                                                                                         | $`\longrightarrow J_{edh,pk}, J_{ekem,pk}, J_{epke,pk}, \sigma^J`$ | Save for $J$                                                                 |

### 4. Source

To begin each session, a source MUST enter (on their first visit) or reenter (on
a subsequent visit) some $passphrase$:

| Source                                                                                          |
| ----------------------------------------------------------------------------------------------- |
| $`S_{dh,sk} \Vert S_{fetch,sk} \Vert S_{pke,sk} \Vert S_{kem,sk} \gets \text{KDF}(passphrase)`$ |

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

A sender knows their own keys. In addition, in the **reply case,** if the sender
is a journalist replying to a source, they also already know their recipient's
keys.

| All senders    | Reply case     |
| -------------- | -------------- |
| $pk_S^{APKE}$  | $pk_R^{APKE}$  |
| $pk_S^{PKE}$   | $pk_R^{PKE}$   |
| $pk_S^{fetch}$ | $pk_R^{fetch}$ |
| $sk_S^{APKE}$  |
| $sk_S^{PKE}$   |
| $sk_S^{fetch}$ |

For some newsroom $NR$ and all its enrolled journalists $J_i$:

| Sender                                                                                                               |                                 | Server                                                                        |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------- |
|                                                                                                                      | $\longrightarrow$ `RequestKeys` |                                                                               |
|                                                                                                                      |                                 | $`pks = \{(pk_{R,i}^{APKE}, pk_{R,i}^{PKE}, pk_{R,i}^{fetch})\}`$ for all $i$ |
|                                                                                                                      | $`pks \longleftarrow`$          |                                                                               |
| **TODO:** verification per $NR$ and $J_i$                                                                            |                                 |                                                                               |
|                                                                                                                      |                                 |                                                                               |
| **Reply case:** The journalist replaces their own keys with those of the source to whom they are replying:           |                                 |                                                                               |
| $`pks \gets pks \setminus \{pk_S^{APKE}, pk_S^{PKE}, pk_S^{fetch}\} \cup \{pk_R^{APKE}, pk_R^{PKE}, pk_R^{fetch}\}`$ |                                 |                                                                               |

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

A receiver knows their own keys.

| All receivers  |
| -------------- |
| $pk_R^{APKE}$  |
| $pk_R^{PKE}$   |
| $pk_R^{fetch}$ |
| $sk_R^{APKE}$  |
| $sk_R^{PKE}$   |
| $sk_R^{fetch}$ |

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
[^4]: TODO kept inline above.
-->

<!--
[^6]: TODO kept inline above.
-->

[^7]:
    The source's keys are considered "permanent" because they are derived
    deterministically from the source's passphrase, which cannot be changed.

[^8]:
    $\mathcal{E}_H \subset \mathbb{Z}$ per Definition 4 of Alwen et al.
    (2020), ["Analyzing the HPKE Standard"][alwen2020].

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
[RFC 9180 §7.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-key-encapsulation-mechanism
[RFC 9180 §7.2]: https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd
