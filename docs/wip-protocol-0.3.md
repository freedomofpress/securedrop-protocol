## Keys

In the table below:

> For keys, we use the notation $X_{A,B}$, where $X$ represents the key owner
> ($`X \in \{NR, J, S\}`$ [for newsroom, journalist, and source, respectively]),
> $A$ represents the key's usage ($`A \in \{sig,fetch,pke,pq,md\}`$), and is prefixed
> with an "e" if the key is a one-time key. $B$ indicates whether the component is
> private or public. For Diffie-Hellman keys $x$, the public component is
> represented by the exponentiation $DH(g, x)$.

| Owner      | Private/Decaps   | Public/Encaps    | Usage                   | Alg       | Signed by        |
| ---------- | ---------------- | ---------------- | ----------------------- | --------- | ---------------- |
| FPF        | $`FPF_{sig,sk}`$ | $`FPF_{sig,pk}`$ | Signing                 |  ?        |                  |
| Newsroom   | $`NR_{sig,sk}`$  | $`NR_{sig,pk}`$  | Signing                 |  ?        | $`FPF_{sig,sk}`$ |
| Journalist | $`J_{sig,sk}`$   | $`J_{sig,pk}`$   | Signing (long-term)     |  ?        | $`NR_{sig,sk}`$  |
| Journalist | $`J_{fetch,sk}`$ | $`J_{fetch,pk}`$ | Fetching (med-term)     | 25519     | $`NR_{sig,sk}`$* |
| Journalist | $`J_{epq,sk}`$   | $`J_{epq,pk}`$   | Msg enc PSK (one-time)  | MLKEM-768 | $`J_{sig,sk}`$   |
| Journalist | $`J_{epke,sk}`$  | $`J_{epke,pk}`$  | Msg enc (one-time)      | DH-AKEM** | $`J_{sig,sk}`$   |
| Journalist | $`J_{emd,sk}`$   | $`J_{emd,pk}`$   | Metatada enc (one-time) | XWING     | $`J_{sig,sk}`$   |
| Source     | $`S_{fetch,sk}`$ | $`S_{fetch,pk}`$ | Fetching                | 25519     |                  |
| Source     | $`S_{pq,sk}`$    | $`S_{pq,pk}`$    | Msg enc PSK             | MLKEM-768 |                  |
| Source     | $`S_{pke,sk}`$   | $`S_{pke,pk}`$   | Msg enc                 | DH-AKEM** |                  | 
| Source     | $`S_{md,sk}`$    | $`S_{md,pk}`$    | Metadata enc            | XWING     |                  |


## Message flow overview
### Send
- Sender (source) creates message and encrypts for each recipient (journalist) individually. Messages are encrypted using HPKE's AuthPSK mode. The "PSK" is $`R_{pq,pk}.encaps()`$ ($`J_{epq,pk}.encaps()`$ for journalist recipients).
  - The message includes the (rest of the) sender pubkey bundle (XWING key, MLKEM key), needed to send replies. It also includes some identifier for the DH-AKEM key (eg a hash) for authentication purposes.***
- Sender encrypts message metadata using HPKE Base (unauthenticated) mode (per 9.9 [Metadata protection](https://www.rfc-editor.org/rfc/rfc9180.html#name-metadata-protection)). "Metadata" includes:
  - the encapsulated PSK secret (recipient: decaps to get PSK, then pass to HPKE.OpenAuthPSK)
  - the encapsulated DH-AKEM message secret (recipient: pass to HPKE.OpenAuthPSK)
  - the sender's own DH-AKEM pubkey (needed for HPKE.OpenAuthPSK)
- Sender creates message "clue" (DH agreement) based on the recipient fetching key and a one-time DH pubkey.
- Sender sends an envelope, representing the entire payload to the sever, that contains:
  - the message ciphertext (classical/PQ hybrid via HPKEAuthPSK)
  - the sealed metadata (hybrid via XWING)
  - the encapsulation of the metadata shared secret (hybrid via XWING)
  - the two parts of the mgdh/"clue" (ephemeral DH pubkey + clue) (classical, plaintext pubkey + key agreement output)

### Fetch
- Discussed separately below

### Read (decrypt)
(Presumes already retrieved encrypted payload via fetch mechanism) 
- Recipient parses payload into metadata and ciphertext
- Recipient opens unauthenticated metadata (hybrid XWING encrypted): `HPKE_METADATA.Open(shared_md_secret_encaps, self.metadata_decaps_key, HPKE_INFO, HPKE_AAD, ct=cmetadata)`
- Recipient parses untrusted metadata into: sender DH-AKEM key, message DH-AKEM shared secret, message PSK shared secret
- Recipient decapsulates message PSK secret using $`R_{pq,sk}`$
- Recipient opens authenticated-sealed ciphertext using HPKE.OpenAuth: `HPKE_MESSAGE.OpenAuth(shared_dhakem_secret_encaps, self.dhakem_decaps_key, HPKE_INFO, HPKE_AAD, ct=cmessage, psk=psk_untrusted, psk_id=HPKE_PSK_ID, pk_s=sender_pkey_bytes_untrusted)`
- Recipient performs any needed checks (eg check plaintext and ensure keys provided in unauthenticated-sealed metadata match keys/key identifiers in plaintext)

### Message flow notes
- Presumes Newsroom PKI set up (ie FPF has signed Newsroom key, newsroom has signed journalist signing keys. Still TBD whether newsroom or journalist signs journo fetching key.)
- Fetching key lifetime still TBD; might want to make it easier to roll than the journo signing key
- Presumes source verifies signatures on keys before using (omits error checking)
- Source creates message for each journalist individually (n journalists)
- Journalist creates reply for all other journalists + source (n-1 + 1 = n, to be sure that ciphertext numbers match in each direction and avoid attacks that allow for probabilistically identifying a user's role)
- Still for discussion: when key fetch happens (re: key exhaustion, re: avoiding as much timing leakage as possible about lurkers/instance traffic)
- Still for discussion: Message (plaintext) structure. Includes at minimum the pubkeys needed for replies, but could also include NR key/identifier (avoid cross-instance replays), additional application-level metadata.
- "Clue" (output of DH agreement) needs to be exposed by whatever primitives library we are using.
- Error-handling/robust implementation details omitted for clarity for now

*: Discussion of whether NR or Journalist signing key signs fetch key. 
**: HPKE ciphersuites are specified as (KEM, KDF, AEAD). DHKEM/DH-AKEM is a Diffie-Hellman based KEM specified (Group, KDF), where the KDFs are permitted to be different. We plan (DH-AKEM, HKDF, AES-GCM) where DH-AKEM is a DH-KEM(X25519, HKDF-SHA256) which is DHKEM 0x0020 in http://rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem
***: In a unidirectional dead-drop mode, attaching these PQ keys could be avoided, since they are only used for replies.

## Message fetch overview

