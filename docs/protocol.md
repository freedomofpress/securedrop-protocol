## Keys summary
 * **FPF**:
     * *FPF<sub>SK</sub>*: Long term FPF signing private key
     * *FPF<sub>PK</sub>*: Long term FPF signing public key
 * **Newsroom**:
     * *NR<sub>SK</sub>*: Long term Newsroom signing private key
     * *NR<sub>PK</sub>*: Long term Newsroom signing public key
 * **Journalists**:
     * *J<sub>SK</sub>*: Long term Journalist signing private key
     * *J<sub>PK</sub>*: Long term Journalist signing public key
     * *JC<sub>SK</sub>*: Long term Journalist message-fetching private key
     * *JC<sub>PK</sub>*: Long term Journalist message-fetching public key
     * *JE<sub>SK</sub>*: Ephemeral per-message key-agreement private key
     * *JE<sub>PK</sub>*: Ephemeral per-message key-agreement public key
 * **Sources**:
     * *PW*: Secret passphrase, per the `SOURCE_PASSPHRASE_*` parameters defined [above](#config)
     * *S<sub>SK</sub>*: Long term Source key-agreement private key
     * *S<sub>PK</sub>*: Long term Source key-agreement public key
     * *SC<sub>SK</sub>*: Long term Source message-fetching private key
     * *SC<sub>PK</sub>*: Long term Source message-fetching public key
 * **Messages**:
     * *ME<sub>SK</sub>*: Ephemeral per-message key-agreement private key
     * *ME<sub>PK</sub>*: Ephemeral per-message key-agreement public key
 * **Server**:
     * *RE<sub>SK</sub>*: Ephemeral Server, per-request message-fetching private key
     * *RE<sub>PK</sub>*: Ephemeral Server, per-request message-fetching public key
     * *DE<sup>n</sup><sub>PK</sub>*: Per-request, ephemeral decoy public key

## Functions
| Formula | Description |
|---|---|
| *c = Enc(k, m)* | Authenticated encryption of message *m* to ciphertext *c* using symmetric key *k* |
| *m = Dec(k, c)* | Authenticated decryption of ciphertext *c* to message *m* using symmetric key *k* |
| *h = Hash(m)* | Hash message *m* to hash *h* |
| *k = KDF(m)* | Derive a key *k* from message *m* |
| *SK = Gen(s)* | Generate a private key *SK* pair using seed *s*; if seed is empty generation is securely random |
| *PK = GetPub(SK)* | Get public key *PK* from secret key *SK* |
| *sig<sup>signer</sup>(target<sub>PK</sub>) = Sign(signer<sub>SK</sub>, target<sub>PK</sub>)* | Create signature *sig* using *signer<sub>SK</sub>* as the signer key and *target<sub>PK</sub>* as the signed public key |
| *true/false = Verify(signer<sub>PK</sub>,sig<sup>signer</sup>(target<sub>PK</sub>))* | Verify signature sig of public key PK using Ver<sub>PK</sub> |
| *k = DH(A<sub>SK</sub>, B<sub>PK</sub>) == DH(A<sub>PK</sub>, B<sub>SK</sub>)* | Generate shared key *k* using a key agreement primitive |

## Keys setup

 * **FPF**:

     | Operation | Description |
     |---|---|
     | *FPF<sub>SK</sub> = Gen()* | FPF generates a random private key (we might add HSM requirements, or certificate style PKI, i.e.: self signing some attributes) |
     | *FPF<sub>PK</sub> = GetPub(FPF<sub>SK</sub>)* | Derive the corresponding public key |

    **FPF** pins *FPF<sub>PK</sub>* in the **Journalist** client, in the **Source** client and in the **Server** code.

 * **Newsroom**:

     | Operation | Description |
     |---|---|
     | *NR<sub>SK</sub> = Gen()* | Newsroom generates a random private key with similar security to the FPF one |
     | *NR<sub>PK</sub> = GetPub(<sub>SK</sub>)* | Derive the corresponding public key |
     | *sig<sup>FPF</sup>(NR<sub>PK</sub>) = Sign(FPF<sub>SK</sub>, NR<sub>PK</sub>)* | Newsroom sends a CSR or the public key to FPF; FPF validates manually/physically before signing |

    **Newsroom** pins *NR<sub>PK</sub>* and *sig<sup>FPF</sup>(NR<sub>PK</sub>)* in the **Server** during initial server setup.

 * **Journalist [0-i]**:

     | Operation | Description |
     |---|---|
     | *J<sub>SK</sub> = Gen()* | Journalist generates the long-term signing key randomly |
     | *J<sub>PK</sub> = GetPub(J<sub>SK</sub>)* | Derive the corresponding public key | 
     | *sig<sup>NR</sup>(J<sub>PK</sub>) = Sign(NR<sub>SK</sub>, J<sub>PK</sub>)* | Journalist sends a CSR or the public key to the Newsroom admin/managers for signing |
     | *JC<sub>SK</sub> = Gen()* | Journalist generates the long-term message-fetching key randomly (TODO: this key could be rotated often) |
     | *JC<sub>PK</sub> = GetPub(JC<sub>SK</sub>)* | Derive the corresponding public key |
     | *sig<sup>J</sup>(JC<sub>PK</sub>) = Sign(J<sub>SK</sub>, JC<sub>PK</sub>)* | Journalist signs the long-term message-fetching key with the long-term signing key |
     | *<sup>[0-n]</sup>JE<sub>SK</sub> = Gen()* | Journalist generates a number *n* of ephemeral key agreement keys randomly |
     | *<sup>[0-n]</sup>JE<sub>PK</sub> = GetPub(<sup>[0-n]</sup>JE<sub>SK</sub>)* | Derive the corresponding public keys |
     | *<sup>[0-n]</sup>sig<sup>J</sup>(<sup>[0-n]</sup>JE<sub>PK</sub>) = Sign(J<sub>SK</sub>, <sup>[0-n]</sup>JE<sub>PK</sub>)* | Journalist individually signs the ephemeral key agreement keys (TODO: add ephemeral key expiration) |

    **Journalist** sends *J<sub>PK</sub>*, *sig<sup>NR</sup>(J<sub>PK</sub>)*, *JC<sub>PK</sub>*, *sig<sup>J</sup>(JC<sub>PK</sub>)*, *<sup>[0-n]</sup>JE<sub>PK</sub>* and *<sup>[0-n]</sup>sig<sup>J</sup>(<sup>[0-n]</sup>JE<sub>PK</sub>)* to **Server** which verifies and publishes them.

 * **Source [0-j]**:

     | Operation | Description |
     |---|---|
     | *PW* = Gen() | Source generates a secure passphrase which is the only state available to clients|
     | *S<sub>SK</sub> = Gen(KDF(encryption_salt \|\| PW))* | Source deterministically generates the long-term key agreement key-pair using a specific hard-coded salt |
     | *S<sub>PK</sub> = GetPub(S<sub>SK</sub>)* | Derive the corresponding public key |
     | *SC<sub>SK</sub> = Gen(KDF(fetching_salt \|\| PW))* | Source deterministically generates the long-term fetching key-pair using a specific hard-coded salt |
     | *SC<sub>PK</sub> = GetPub(SC<sub>SK</sub>)* | Derive the corresponding public key |

    **Source** does not need to publish anything until the first submission is sent.

## Messaging protocol overview
Only a source can initiate a conversation; there are no other choices as sources are effectively unknown until they initiate contact first.

See the ["Flow Chart"](#flow-chart) section for a summary of the asymmetry in this protocol.

### Source submission to Journalist
 1. *Source* fetches *NR<sub>PK</sub>*, *sig<sup>FPF</sup>(NR<sub>PK</sub>)*
 2. *Source* checks *Verify(FPF<sub>PK</sub>,sig<sup>FPF</sup>(NR<sub>PK</sub>)) == true*, since FPF<sub>PK</sub> is pinned in the Source client
 3. For every *Journalist* (i) in *Newsroom*
     - *Source* fetches *<sup>i</sup>J<sub>PK</sub>*, *<sup>i</sup>sig<sup>NR</sup>(<sup>i</sup>J<sub>PK</sub>)*, *<sup>i</sup>JC<sub>PK</sub>*, *<sup>i</sup>sig<sup>iJ</sup>(<sup>i</sup>JC<sub>PK</sub>)*
     - *Source* checks *Verify(NR<sub>PK</sub>,<sup>i</sup>sig<sup>NR</sup>(<sup>i</sup>J<sub>PK</sub>)) == true*
     - *Source* checks *Verify(<sup>i</sup>J<sub>PK</sub>,<sup>i</sup>sig<sup>iJ</sup>(<sup>i</sup>JC<sub>PK</sub>)) == true*
     - *Source* fetches *<sup>ik</sup>JE<sub>PK</sub>*, *<sup>ik</sup>sig<sup>iJ</sup>(<sup>ik</sup>JE<sub>PK</sub>)* (k is random from the pool of non-used, non-expired, *Journalist* ephemeral keys)
     - *Source* checks *Verify(<sup>i</sup>J<sub>PK</sub>,<sup>ik</sup>sig<sup>iJ</sup>(<sup>ik</sup>JE<sub>PK</sub>)) == true*
 4. *Source* generates the unique passphrase randomly *PW = G()* (the only state that identifies the specific *Source*)
 5. *Source* derives *S<sub>SK</sub> = G(KDF(encryption_salt + PW))*, *S<sub>PK</sub> = GetPub(S<sub>SK</sub>)*
 6. *Source* derives *SC<sub>SK</sub> = G(KDF(fetching_salt + PW))*, *SC<sub>PK</sub> = GetPub(SC<sub>SK</sub>)*
 7. *Source* splits any attachment in parts of size `commons.CHUNKS`. Any chunk smaller is padded to `commons.CHUNKS` size.
 8. For every *Chunk*, *<sup>m</sup>u*
    - *Source* generate a random key *<sup>m</sup>s = G()*
    - *Source* encrypts *<sup>m</sup>u* using *<sup>m</sup>s*: *<sup>m</sup>f = E(<sup>m</sup>s, <sup>m</sup>u)*
    - *Source* uploads *<sup>m</sup>f* to *Server*, which returns a random token <sup>m</sup>t (`file_id`)
    - *Server* stores <sup>m</sup>t -> *<sup>m</sup>f* (`file_id` -> `file`)
 9. *Source* adds metadata, *S<sub>PK</sub>*, *SC<sub>PK</sub>* to message *m*.
 10. *Source* adds all the *<sup>[0-m]</sup>s* keys and all the tokens <sup>[0-m]</sup>t (`file_id`) to message *m*
 11. *Source* pads the resulting text to a fixed size: *mp = Pad(message, metadata, S<sub>PK</sub>, SC<sub>PK</sub>, <sup>[0-m]</sup>s, <sup>[0-m]</sup>t)*
 12. For every *Journalist* (i) in *Newsroom* 
     - *Source* generates *<sup>i</sup>ME<sub>SK</sub> = Gen()* (random, per-message secret key)
     - *Source* derives the corresponding public key *<sup>i</sup>ME<sub>PK</sub> = GetPub(<sup>i</sup>ME<sub>SK</sub>)* (`message_public_key`)
     - *Source* derives the shared encryption key using a key-agreement primitive *<sup>i</sup>k = DH(<sup>i</sup>ME<sub>SK</sub>,<sup>i</sup>JE<sub>PK</sub>)*
     - *Source* encrypts *mp* using *<sup>i</sup>k*: *<sup>i</sup>c = Enc(<sup>i</sup>k, mp)* (`message_ciphertext`)
     - *Source* calculates *mgdh = DH(<sup>i</sup>ME<sub>SK</sub>,<sup>i</sup>JC<sub>PK</sub>)* (`message_gdh`)
     - *Source* discards <sup>i</sup>ME<sub>SK</sub> to ensure forward secrecy
     - *Source* sends *(<sup>i</sup>c,<sup>i</sup>ME<sub>PK</sub>,<sup>i</sup>mgdh)* to *Server*
     - *Server* generates *<sup>i</sup>mid = Gen()* (`message_id`) and stores *<sup>i</sup>mid* -> *(<sup>i</sup>c,<sup>i</sup>ME<sub>PK</sub>,<sup>i</sup>mgdh)* (`message_id` -> (`message_ciphertext`, `message_public_key`, `message_gdh`))


### Server message id fetching protocol
 1. For every entry *<sup>i</sup>mid* -> *<sup>i</sup>ME<sub>PK</sub>*, *<sup>i</sup>mgdh* (`message_id` -> (`message_gdh`, `message_public_key`)):
     - *Server* generates per-request, per-message, ephemeral secret key *<sup>i</sup>RE<sub>SK</sub> = Gen()*
     - *Server* calculates *<sup>i</sup>kmid = DH(<sup>i</sup>RE<sub>SK</sub>,<sup>i</sup>mgdh)*
     - *Server* calculates *<sup>i</sup>pmgdh = DH(<sup>i</sup>RE<sub>SK</sub>,<sup>i</sup>ME<sub>PK</sub>)*
     - *Server* encrypts *<sup>i</sup>mid* using *<sup>i</sup>kmid*: *<sup>i</sup>enc_mid = Enc(<sup>i</sup>kmid, <sup>i</sup>mid)*
     - *Server* discards *<sup>i</sup>RE<sub>SK</sub>*
  2. *Server* generates *j = [`commons.MAX_MESSAGES - i`]* random decoys *<sup>[0-j]</sup>decoy_pmgdh* and *<sup>[0-j]</sup>decoy_enc_mid*
  3. *Server* returns a shuffled list of `commons.MAX_MESSAGES` (*i+j*) tuples of *(<sup>[0-i]</sup>pmgdh,<sup>[0-i]</sup>enc_mid) U (<sup>[0-j]</sup>decoy_pmgdh,<sup>[0-j]</sup>enc_mid)*


### Source message id fetching protocol
  1. *Source* derives *SC<sub>SK</sub> = G(KDF(fetching_salt + PW))*
  2. *Source* fetches *(<sup>[0-n]</sup>pmgdh,<sup>[0-n]</sup>enc_mid)* from *Server* (`n=commons.MAX_MESSAGES`)
  3. For every *(<sup>i</sup>pmgdh,<sup>i</sup>enc_mid)*:
     - *Source* calculates *<sup>i</sup>kmid = DH(<sup>i</sup>pmgdh,SC<sub>SK</sub>)*
     - *Source* attempts to decrypt *<sup>i</sup>mid = Dec(<sup>i</sup>kmid,<sup>i</sup>enc_mid)*
     - If decryption succeeds, save *<sup>i</sup>mid*

### Journalist message id fetching protocol
  1. *Journalist* fetches *(<sup>[0-n]</sup>pmgdh,<sup>[0-n]</sup>enc_mid)* from *Server* (`n=commons.MAX_MESSAGES`)
  2. For every *(<sup>i</sup>pmgdh,<sup>i</sup>enc_mid)*:
     - *Journalist* calculates *<sup>i</sup>kmid = DH(<sup>i</sup>pmgdh,JC<sub>SK</sub>)*
     - *Journalist* attempts to decrypt *<sup>i</sup>mid = Dec(<sup>i</sup>kmid,<sup>i</sup>enc_mid)*
     - If decryption succeeds, save *<sup>i</sup>mid*


### Journalist read
 1. *Journalist* fetches from *Server* *mid* -> (*c*, *ME<sub>PK</sub>*) (`message_id` -> (`message_ciphertext`, `message_public_key`))
 2. For every unused  *Journalist* ephemeral key *<sup>i</sup>JE<sub>SK</sub>*
     - *Journalist* calculates a tentative encryption key using the key agreemenet primitive *<sup>i</sup>k = DH(<sup>i</sup>JE<sub>SK</sub>, ME<sub>PK</sub>)*
     - *Journalist* attempts to decrypt *mp = Dec(<sup>i</sup>k, c)*
     - *Journalist* verifies that *mp* decrypted successfully, if yes exits the loop
 3. *Journalist* removes padding from the decrypted message: *(message, metadata, *S<sub>PK</sub>*, *SC<sub>PK</sub>*, *<sup>[0-m]</sup>s*, *<sup>[0-m]</sup>t*) = Unpad(mp)*
 4. For every attachment *Chunk* token *<sup>m</sup>t*
     - *Journalist* fetches from *Server* *<sup>m</sup>t* -> *<sup>m</sup>f* (`file_id` -> `file`)
     - *Journalist* decrypts *<sup>m</sup>f* using *<sup>m</sup>s*: *<sup>m</sup>u = Dec(<sup>m</sup>s, <sup>m</sup>)f*
 5. *Journalist* joins *<sup>m</sup>u* according to metadata and saves back the original files
 6. *Journalist* reads the message *m*

### Journalist reply
 1. *Journalist* has plaintext *mp*, which contains also *S<sub>PK</sub>* and SC<sub>PK</sub>
 2. *Journalist* generates *ME<sub>SK</sub> = Gen()* (random, per-message secret key)
 3. *Journalist* derives the shared encryption key using a key-agreement primitive *k = DH(ME<sub>SK</sub>,S<sub>PK</sub>)*
 4. *Journalist* pads the text to a fixed size: *mp = Pad(message, metadata)* (note: Journalist can potetially attach *<sup>r</sup>JE<sub>PK</sub>,JC<sub>PK</sub>*)
 5. *Journalist* encrypts *mp* using *k*: *c = Enc(k, mp)*
 6. *Journalist* calculates *mgdh = DH(ME<sub>SK</sub>,SC<sub>PK</sub>)* (`message_gdh`)
 7. *Journalist* discards *ME<sub>SK</sub>*
 8. *Journalist* sends *(c,ME<sub>PK</sub>,mgdh)* to *Server*
 9. *Server* generates *mid = Gen()* (`message_id`) and stores *mid* -> *(c,ME<sub>PK</sub>,mgdh)* (`message_id` -> (`message_ciphertext`, `message_public_key`, `message_gdh`))

### Source read
 1. *Source* fetches from *Server* *mid* -> (*c*, *ME<sub>PK</sub>*) (`message_id` -> (`message_ciphertext`, `message_public_key`))
 2. *Source* derives *S<sub>SK</sub> = G(KDF(encryption_salt + PW))*
 3. *Source* calculates the shared encryption key using a key agreement protocol *k = DH(S<sub>SK</sub>, ME<sub>PK</sub>)*
 4. *Source* decrypts the message using *k*: *mp = Dec(k<sup>k</sup>, c)*
 5. *Source* removes padding from the decrypted message: *m = Unpad(mp)*
 6. *Source* reads the message and the metadata

### Source reply
*Source* replies work the exact same way as a first submission, except the source is already known to the *Journalist*. As an additional difference, a *Journalist* might choose to attach their (and eventually others') keys in the reply, so that *Source* does not have to fetch those from the server as in a first submission.

### Flow Chart

![chart](imgs/sd_schema.png)

For simplicity, in this chart, messages are sent to a single *Journalist* rather than to all journalists enrolled with a given newsroom, and the attachment submission and retrieval procedure is omitted.

Observe the asymmetry in the client-side operations:

| Routine | Journalist fetch and decrypt | Source fetch and decrypt |
| --- | --- | --- |
| **Leg** | **message_ciphertext,ME<sub>PK</sub>** | **message_ciphertext,ME<sub>PK</sub>** |
| Step 1. | k = DH(ME<sub>PK</sub>,<sup>i</sup>JE<sub>SK</sub>) | k = DH(ME<sub>PK</sub>,S<sub>SK</sub>) |
| Step 2. | Discard(<sup>i</sup>JE<sub>SK</sub>) |
| Step 3. | S<sub>PK</sub>,SC<sub>PK</sub>,m = Dec(k,message_ciphertext) | <sup>m</sup>JE<sub>PK</sub>,JC<sub>PK</sub>,m = Dec(k,message_ciphertext) |