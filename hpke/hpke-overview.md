# Protocol comparison

## pqxdh-g vs l-hpke cage match
(omit NR for now)

| property | pqxdh-g | l-hpke | notes |
|----------------|---------|--------|-------|
| pt Message | IK<sub>A</sub> \|\| Enc(SK<sub>inner</sub>, hash(pt) \|\| pt) | pt \|\| S<sub>fetch</sub> \|\| S<sub>dh-akem</sub> \|\| S<sub>kem.pq</sub> \|\| S<sub>pke</sub> \|\| J<sub>sig</sub> | Not a fair comparison, still need to address source key advertising in pqxdh-g |
| Message encryption key inputs | KDF(DH<sub>2</sub> \|\| DH<sub>3</sub> \|\| DH<sub>4</sub> \|\| SS) | KDF(KemCombiner(DH-AKEM.AuthEncap(skS, pkR<sub>dh</sub>) [includes ephemeral dh message key], PQEncap(pkR<sub>kem</sub>))) | pqxdh-g: DH between ephemeral key and Bob keys |
| Message encryption includes sender identity input | no | yes | pqxdh-g includes identity-signed hash in msg instead |
| Message-level deniability | yes | yes | |
| Envelope additional content | EK<sub>A</sub>, PQEncaps(PQPK<sub>B</sub>) | DH-AKEM.AuthEncap(pkR), KEM.Encaps(pkR<sub>kem</sub>), pkS<sub>dh</sub> | confirming: non-message envelope contents are not pq encrypted, therefore pkS<sub>dh</sub> is not pq encrypted in l-hpke? |
| Envelope additional content encryption |  ? | PKE | |
| Decryption complexity (journo) | Linear | todo | |
| Key exhaustion | addressed (last resort) | todo | |
| Forged message detected when? | After final decryption | At message decryption | |

## Recap: classic HPKE AuthEncap/AuthEncrypt (non-PQ)

(Note: aad, info are optional per RFC9180, and L's implementation does not use them, so "" for clarity here)

    def AuthEnc(skSᵈʰ, pkRᵈʰ, m, aad="", info=""): # "SealAuth" in HPKE RFC
        c₁, k₁ <- DH-AKEM.AuthEncap(skSᵈʰ, pkRᵈʰ)
        k || nonce <- F(k₁, info="")
        c <- AEAD.Enc(k, m, aad="", nonce)
        return (c₁, c) # enc, ct aka encapsulated KEM shared secret + ciphertext

    def DH-AKEM.AuthEncap(pkR, skS):
        skE, pkE = GenerateKeyPair()
        dh1 = DH(skS, pkR)
        dh2 = DH(skE, pkR)
        dh = concat(dh2, dh1)
        enc = SerializePublicKey(pkE)

        pkRm = SerializePublicKey(pkR)
        pkSm = SerializePublicKey(pk(skS))
        kem_context = concat(enc, pkRm, pkSm)

        shared_secret = ExtractAndExpand(dh, kem_context) # dh1 || dh2 || pkE || pkR || pkS into a KDF
        return shared_secret, enc # the only part that the other party needs to solve the shared secret is `enc` aka the ephemeral pubkey, they have everything else

## l-hpke

NR = Newsroom pubkey

#### Journalist keys summary (wip?/needs check)
| Name | Definition | Usage |
|------|-----------|---|
| J<sub>sig</sub> | Journalist's signing identity key | Signing |
| J<sub>fetch</sub> | Journalist's fetching key | Fetching |
| J<sub>dh-akem</sub> | Journalist DH identity key | DH-AKEM |
| J<sub>ekem.pq</sub> | Journalist's ephemeral PQ KEM key | PQKEM (epehemeral) |
| J<sub>epke</sub> | Journalist's set one-time public key encryption keys | PKE (ephemeral) |
| J<sub>edh-kem</sub> | Journalist's set one-time DH keys | DH-KEM (ephemeral) |
| x | Per-message ephemeral key | DH |


#### Sources keys summary
| Name | Definition | Usage |
|------|-----------|---|
| S<sub>fetch</sub> | Source fetching key | Fetching
| S<sub>dh-akem</sub>| Source identity key  | DH-AKEM |
| S<sub>kem.pq</sub> | Source PQ KEM key | PQKEM |
| S<sub>pke</sub> |Source public-key encryption key | PKE |
| x | Per-message ephemeral key | DH |

### Overview

Source includes all their pubkeys in the message, plus the intended recipient key J<sub>sig</sub> and newsroom key

m <- msg || S<sub>fetch</sub> || S<sub>dh-akem</sub> || S<sub>kem.pq</sub> || S<sub>pke</sub> || J<sub>sig</sub> || NR

Source performs HPKE<sup>pq</sup><sub>AuthEnc</sub> on m

  AuthEnc(Sksᵈʰ, (pkRᵈʰ, pkRₖₑₘ) m, aad="", info="")  -> Modified from AuthEncap, which otherwise supports only one (non-PQ) recipient pubkey
    C₁, K₁ = DH-AKEM.AuthEncap(Sks, pkRᵈʰ) -> standard non PQ AuthEncap
    C₂, K₂ = KEM<sub>pq</sub>.Encap(pkRₖₑₘ) -> added non-auth PQ Encap

    KEM PRF combiner combines the above shared secrets to yield K
    k || Nonce <- K

    use shared secret k and encrypt the message:

    AEAD.Encrypt(k, m, aad="", nonce) -> HPKE.Seal

which returns (C₁, C₂, C)
aka the (non-pq) DH-KEM AuthEncap of the receiver key, the (pq) KEM Encap of the receiver KEM key, and the (pq) ciphertext

Then, the first two elements and the Sourceᵈʰ key are PKE encrypted to J<sub>epke</sub>.

### l-hpke AuthEncap

    def PqAuthEnc(skSᵈʰ, (pkRᵈʰ, pkRₖₑₘ), m, aad="", info=""):
        c₁, k₁ <- DH-AKEM.AuthEncap(skSᵈʰ, pkRᵈʰ) # Unchanged
        c₂, k₂ <- PQKEM.Encap(pkRₖₑₘ) # New

        K <- PRF-KEM-combiner(k₁, c₁||c₂) XOR PRF-KEM-combiner(k₂, c₁||c₂) # Modified

        k || nonce <- F(K, info="") # Unchanged

        c <- AEAD.Enc(k, m, aad="", nonce) # Unchanged
        return ((c₁, c₂), c) # Modified: return 2 receiver key encapsulations instead of 1, plus ciphertext

written longer:

    def PqAuthEnc(pkRᵈʰ, pkRₖₑₘ, skS):
        # AuthEncap (standard)
        skE, pkE = GenerateKeyPair()
        dh1 = DH(skS, pkR)
        dh2 = DH(skE, pkR)
        dh = concat(dh2, dh1)
        enc = SerializePublicKey(pkE)

        pkRm = SerializePublicKey(pkR)
        pkSm = SerializePublicKey(pk(skS))
        kem_context = concat(enc, pkRm, pkSm)

        # (k₁, c₁) = (shared_secret_dh, enc) 
        shared_secret_dh = ExtractAndExpand(dh, kem_context) # dh1 || dh2 || pkE || pkR || pkS
        
        # Added (k₂, c₂) = (ss_pqkem, ss_pqkem_encaps) 
        ss_pqkem, ss_pqkem_encaps = KEM<sub>pq</sub>.Encap(pkR<sub>kem.pq</sub>)

        # rest of owl
        K <- PRF-KEM-combiner(shared_secret_dh, enc||ss_pqkem_encaps) XOR PRF-KEM-combiner(ss_pqkem, enc||ss_pqkem_encaps) # Modified

        k || nonce <- F(K, info="") # Unchanged

        c <- AEAD.Enc(k, m, aad="", nonce) # Unchanged
        return ((enc, ss_pqkem_encaps), c) # Modified: return 2 receiver key encapsulations instead of 1, plus ciphertext

        # Subsequent step: encrypt enc, ss_pqkem_encaps, skS with PKE to receiver ePKE key


