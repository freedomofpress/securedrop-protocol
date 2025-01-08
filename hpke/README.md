## What is this?
In a similar vein to ``dhetm-ish-securedrop.py``, this is a toy implementation of securedrop-protocol based on the Hybrid Public Key Encryption scheme (HPKE) as described in https://datatracker.ietf.org/doc/html/rfc9180#name-introduction.

Note that the "hyrid" of HPKE refers to asymmetric/symmetric hybrid, not PQ/T hybrid, and specifically, to a scheme that generates the symmetric key from an encapsulation of an asymmetric pubkey. The scheme proposed in HPKE, DHKEM, is a KEM constructed with a classical Diffe-Hellman key agreement scheme, against which the security properties of the scheme are proven. The RFC also makes mention of the possibility of using PQ KEMs, although those do not currently support Authentication modes.

### Overview
- From the HPKE RFC: "encrypted messages convey an encryption key encapsulated with a public key scheme, along with one or more arbitrary-sized ciphertexts encrypted using that key."
- HPKE relies on a ciphersuite consisting of: a KEM function, a KDF, and an authenticated encryption algorithm (KEM, KDF, AEAD) (and optionally also on a serialization/deserialization function for private keys).

Other notes:
- "Senders and recipients MUST validate KEM inputs and outputs"
- 4 HPKE "modes" (2 modes, base or auth, * 2 variants, PSK or not). If the selected KEM supports AuthEncap / AuthDecap then all four modes are possible; otherwise, only the first 2 are possible.
- DH-based KEM: "We can construct a KEM [called DHKEM(Group, KDF)] where Group denotes the Diffie-Hellman group and KDF denotes the KDF. The KDF used in DHKEM can be equal to or different from the KDF used in the remainder of HPKE."
- "In the Auth and AuthPSK modes, the recipient is assured that the sender held the private key skS. This assurance is limited for the DHKEM variants defined in this document because of key-compromise impersonation."
- (Asymmetric) auth mode (5.1.3): "This variant extends the base mechanism by allowing the recipient to authenticate that the sender possessed a given KEM private key. This is because AuthDecap(enc, skR, pkS) produces the correct KEM shared secret only if the encapsulated value enc was produced by AuthEncap(pkR, skS), where skS is the private key corresponding to pkS. In other words, at most two entities (precisely two, in the case of DHKEM) could have produced this secret, so if the recipient is at most one, then the sender is the other with overwhelming probability."
- Authenticated modes that use post-quantum algorithms are not well-supported/understood. ML-KEM, for example, does not support AuthEncap()/AuthDecap(): "If non-DH-based KEMs are to be used with HPKE, further analysis will be necessary to prove their security."
- Unidirectional: "The sender's context MUST NOT be used for decryption. Similarly, the recipient's context MUST NOT be used for encryption." (This is relevant outside of single-shot mode)

Other interesting things:
- Single-shot secret export: "Derive a secret key known only to one recipient"
- Metadata protection: "The authenticated modes of HPKE (PSK, Auth, and AuthPSK) require that the recipient know what key material to use for the sender. This can be signaled in applications by sending the PSK ID (psk_id above) and/or the sender's public key (pkS). [...] An application that wishes to protect these metadata values without requiring further provisioning of keys can use an additional instance of HPKE, using the unauthenticated Base mode. Where the application might have sent (psk_id, pkS, enc, ciphertext) before, it would now send (enc2, ciphertext2, enc, ciphertext), where (enc2, ciphertext2) represent the encryption of the psk_id and pkS values. The cost of this approach is an additional KEM operation each for the sender and the recipient."

HPKE non-goals (application-level problems):
(Note: many of these may not apply to us in single-shot mode, but they are interesting.)
- Message ordering
  - if single-shot API is used, point is moot; otherwise, order of decryption must match order of encryption. Also, lost/dropped messages aren't tolerated.
- Algorithm downgrade
- Replays (no guarantees aside from non-loss-tolerance; see again single shot vs ongoing context)
- **Padding**: applications to handle (https://datatracker.ietf.org/doc/html/rfc9180#name-hiding-plaintext-length)
- Encoding: application to handle/specify
- "Only long-term secrets are used on the side of the recipient, so HPKE schemes are not forward secret with respect to recipient key compromise. HPKE ciphertexts are forward secret with respect to sender compromise in all modes. This is because ephemeral randomness is used on the sender's side, which is supposed to be erased directly after computation of the KEM shared secret and ciphertext."
  - Bad local randomness (9.7.5): confidentiality impacts, forward secrecy w.r.t sender compromise may be lost; if KEM shared secret is reused, then same key-nonce pairs used for AEAD, and these are not secure w.r.t nonce reuse. Suggestion: see https://datatracker.ietf.org/doc/html/rfc8937 and combine ephemeral randomness with local long-term secret.
- "The randomness used in Encap() and AuthEncap() to generate the KEM shared secret or its encapsulation MUST NOT be reused elsewhere.
  Since a KEM key pair belonging to a sender or recipient works with all modes, it can be used with multiple modes in parallel. HPKE is constructed to be secure in such settings due to domain separation using the suite_id variable. However, there is no formal proof of security at the time of writing for using multiple modes in parallel; [HPKEAnalysis] and [ABHKLR20] only analyze isolated modes."

### Scope

Per <https://github.com/freedomofpress/securedrop-protocol/issues/55#issuecomment-2454681466>:

- [x] key generation
- [x] minimal source encryption → journalist decryption
- [x] ephemeral source encryption → journalist decryption
  - [ ] verification of $$J$$ and $$NR$$
- [x] ephemeral journalist encryption → source decryption
- [x] ephemeral journalist encryption → journalist decryption
- [x] ephemeral source encryption → source decryption
- [x] KEM
- [ ] restore fetching from <https://gist.github.com/lsd-cat/62b05108d7ed7e974efbb805e35eaf28>
- [ ] tracing like <https://gist.github.com/cfm/c63561609d2bf621d877dbbef052ab1a>

