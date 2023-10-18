# Next-Gen SecureDrop Research

## Highlights
 * All messages are equal
 * There are no accounts
 * Everything is end to end encrypted with one time symmetric keys
 * Source to journalist key agreement has forward secrecy
 * Zero explicit metadata on the server; there are implicit metadata such as access patterns to the API
 * Key isolation: each key is used only for a cryptographic purpose: signing, encryption, message fetching

## Security
For an informal threat model and comparison with other schemes, see the [related wiki page](https://github.com/freedomofpress/securedrop-poc/wiki/Proposals-comparison).

## Config
In `commons.py` there are the following configuration values which are global for all components, even though not all parties need all of them.

| Variable | Value | Components | Description |
|---|---|---|---|
| `SERVER` | `127.0.0.1:5000` | source, journalist | The URL the Flask server listens on; used by both the journalist and the source clients. |
| `DIR` | `keys/` | server, source, journalist | The folder where everybody will load the keys from. There is no separation for demo simplicity but in an actual implementation everybody will only have their keys and the required public one to ensure the trust chain. |
| `UPLOADS` | `files/` | server | The folder where the Flask server will store uploaded files
| `JOURNALISTS` | `10` | server, source |  How many journalists do we create and enroll. In general, this is realistic, in current SecureDrop usage it is way less. For demo purposes everybody knows it, in a real scenario it would not be needed. |
| `ONETIMEKEYS` | `30` | journalist | How many ephemeral keys each journalist create, sign and uploads when required. |
| `CURVE` | `NIST384p` | server, source, journalist | The curve for all elliptic curve operations. It must be imported first from the python-ecdsa library. |
| `MAX_MESSAGES` | `500` | server | How may potential messages the server sends to each party when they try to fetch messages. This basically must be more than the messages in the database, otherwise we need to develop a mechanism to group messages adding some bits of metadata. |
| `CHUNK` | `512 * 1024` | source | The base size of every parts in which attachment are split/padded to. This is not the actual size on disk, cause that will be a bit more depending on the nacl SecretBox implementation. |

## Installation (Qubes)
Install dependencies and create the virtual environment.
```
sudo dnf install redis
sudo systemctl start redis
python3 -m virtualenv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

Generate the FPF root key, the intermediate key, and the journalists long term keys and sign them all hierarchically.
```
python3 pki.py
```

Run the server:
```
FLASK_DEBUG=1 flask --app server run
```

Impersonate the journalists and generate ephemeral keys for each of them. Upload all the public keys and their signature to the server.
```
for i in $(seq 0 9); do python3 journalist.py -j $i -a upload_keys; done;
```

Call/caller charts can be generated with `make docs`.

## Demo

```
bash demo.sh
```

The demo script will clean past keys and files, flush Redis, generate a new PKI, start the server, generate and upload journalists and simulate submissions and replies from different sources/journalists.

## Command-line
### Source
#### Help

```
# python3 source.py -h
usage: source.py [-h] [-p PASSPHRASE] -a {fetch,read,reply,submit,delete} [-i ID] [-m MESSAGE] [-f FILES [FILES ...]]

options:
  -h, --help            show this help message and exit
  -p PASSPHRASE, --passphrase PASSPHRASE
                        Source passphrase if returning
  -a {fetch,read,reply,submit,delete}, --action {fetch,read,reply,submit,delete}
                        Action to perform
  -i ID, --id ID        Message id
  -m MESSAGE, --message MESSAGE
                        Plaintext message content for submissions or replies
  -f FILES [FILES ...], --files FILES [FILES ...]
                        List of local files to submit

```

#### Send a submission (without attachments)
```
# python3 source.py -a submit -m "My first contact message with a newsroom :)"
[+] New submission passphrase: 23a90f6499c5f3bc630e7103a4e63c131a8248c1ae5223541660b7bcbda8b2a9

```
#### Send a submission (with attachments)
```
# python3 source.py -a submit -m "My first contact message with a newsroom with collected evidences and a supporting video :)" -f /tmp/secret_files/file1.mkv /tmp/secret_files/file2.zip 
[+] New submission passphrase: c2cf422563cd2dc2813150faf2f40cf6c2032e3be6d57d1cd4737c70925743f6

```
#### Fetch replies

```
# python3 source.py -p 23a90f6499c5f3bc630e7103a4e63c131a8248c1ae5223541660b7bcbda8b2a9 -a fetch
[+] Found 1 message(s)
    de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca

```

#### Read a reply

```
# python3 source.py -p 23a90f6499c5f3bc630e7103a4e63c131a8248c1ae5223541660b7bcbda8b2a9 -a read -i de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca
[+] Successfully decrypted message de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca

    ID: de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca
    From: a1eb055608e169d04392607a79a3bf8ac4ccfc9e0d3f5056941f31be78a12be1
    Date: 2023-01-23 23:42:14
    Text: This is a reply to the message without attachments, it is identified only by the id

```

#### Send an additional reply

```
# python3 source.py -p 23a90f6499c5f3bc630e7103a4e63c131a8248c1ae5223541660b7bcbda8b2a9 -a reply -i de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca -m "This is a second source to journalist reply"
```

#### Delete a message

```
# python3 source.py -p 23a90f6499c5f3bc630e7103a4e63c131a8248c1ae5223541660b7bcbda8b2a9 -a delete -i de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca
[+] Message de55e92ca3d89de37855cea52e77c182111ca3fd00cf623a11c1f41ceb2a19ca deleted

```

### Journalist
#### Help
```
# python3 journalist.py -h
usage: journalist.py [-h] -j [0, 9] [-a {upload_keys,fetch,read,reply,delete}] [-i ID] [-m MESSAGE]

options:
  -h, --help            show this help message and exit
  -j [0, 9], --journalist [0, 9]
                        Journalist number
  -a {upload_keys,fetch,read,reply,delete}, --action {upload_keys,fetch,read,reply,delete}
                        Action to perform
  -i ID, --id ID        Message id
  -m MESSAGE, --message MESSAGE
                        Plaintext message content for replies

```
#### Fetch replies and submissions

```
# python3 journalist.py -j 7 -a fetch
[+] Found 2 message(s)
    0358306e106d1d9e0449e8e35a59c37c41b28a5e6630b88360738f5989da501c
    1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627

```

#### Read a submission/reply (without attachments)

```
# python3 journalist.py -j 7 -a read -i 1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627
[+] Successfully decrypted message 1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627

    ID: 1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627
    Date: 2023-01-23 23:37:15
    Text: My first contact message with a newsroom :)

```

#### Read a submission/reply (with attachments)

```
# python3 journalist.py -j 7 -a read -i 0358306e106d1d9e0449e8e35a59c37c41b28a5e6630b88360738f5989da501c
[+] Successfully decrypted message 0358306e106d1d9e0449e8e35a59c37c41b28a5e6630b88360738f5989da501c

    ID: 0358306e106d1d9e0449e8e35a59c37c41b28a5e6630b88360738f5989da501c
    Date: 2023-01-23 23:38:27
    Attachment: name=file1.mkv;size=1562624;parts_count=3
    Attachment: name=file2.zip;size=93849;parts_count=1
    Text: My first contact message with a newsroom with collected evidences and a supporting video :)

```

#### Send a reply

```
# python3 journalist.py -j 7 -a reply -i 1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627 -m "This is a reply to the message without attachments, it is identified only by the id"
```

#### Delete a message

```
# python3 journalist.py -j 7 -a delete -i 1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627
[+] Message 1216789eab54869259e168b02825151b665f04b0b9f01f654c913e3bbea1f627 deleted

```

## Parties
  * **Source(s)**: A source is someone who wants to leak a document. A source is unknown prior its first contact. A source may want to send a text message and/or add attachments. The anonymity and safety of the source is vital. The source must use Tor Browser to preserve their anonymity and no persistence shall be required. The highest degree of deniability a source has, the better.
  * **Journalist(s)**: Journalists are those designated to receive, check and reply to submissions. Journalists are known, or at least the newsroom they work for is known and trusted. Journalists are expected to use the SecureDrop Workstation with an ad-hoc client, which has dedicated encrypted storage.
  * **Newsroom**: A newsroom is the entity responsible or at least with formal ownership of a SecureDrop instance. The newsroom is trusted, and is expected to publish their SecureDrop instance somewhere, their tips page, their social media channel or wherever they want the necessary outreach. In the traditional model, newsroom are also technically in charge of their own server instances and of journalist enrollment.
  * **FPF**: FPF is the entity responsible for maintaining and developing SecureDrop. FPF can offer additional services, such as dedicated support. FPF has already a leading role, in the context that, while the project is open source, releases and Onion Lists for Tor Browser are signed with FPF keys. However, the full stack must remain completely usable without any FPF involvement or knowledge.

## Notions
  * **Keys**: When referring to keys, either symmetric or asymmetric, depending on the context, the key storage back-end (ie: the media device) may eventually vary. Especially long term keys can be stored on Hardware Security Modules or Smart Cards, and signing keys might also be a combination of multiple keys with special requirements (ie: 3 out of 5 signers)
  * **Server**: For this project a server might be a physical dedicated server housed in a trusted location, a physical server in an untrusted location, or a virtual server in a trusted or untrusted context. Besides the initial setup, all the connection to the server have to happen though the Tor Hidden Service Protocol. However, we can expect that a powerful attacker can find the server location and provider (through financial records, legal orders, de-anonymization attacks, logs of the setup phase).

## Threat model summary
 * *FPF*
     * Is generally trusted
     * Is based in the US
     * Might get compromised technically
     * Might get compromised legally
     * Develop all the components ans signs them
     * Enrolls newsrooms

 * *Newsroom*
     * Is generally trusted
     * Can be based anywhere
     * Might get compromised legally
     * Might get compromised technically
     * Manage a server instance
     * Enrolls journalists

 * *Server*
     * Is generally untrusted
     * Compromise require effort
     * There might be backup and snapshots from every point in time
     * RAM might be silently read
     * Managed and paid for by *Newsroom* or third party for them 

 * *Journalist*
     * Number can vary per *Newsroom*
     * Is generally trusted
     * Can travel
     * Physical and endpoint security depends on the workstation and client; out of scope here
     * Can be compromised occasionally
     * Read submissions
     * Reply to submissions
     * Identity id generally known

 * *Source*:
     * Is completely untrusted
     * Anybody can be a source at anytime
     * Identity is secret
     * Can read journalist replies to them
     * Can send messages to journalists
     * Can attach files

 * *Submission*:
     * Always from source to journalist
     * Generally specific for a single instance
     * Can be anything
     * Content is secret
     * Origin is secret


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
     * *PW*: Secret passphrase
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
     | *FPF<sub>SK</sub> = Gen()* | FPF generates a random privatekey (we might add HSM requirements, or certificate style PKI, ie: self signing some attributes) |
     | *FPF<sub>PK</sub> = GetPub(FPF<sub>SK</sub>)* | Derive the corresponding public key |

    **FPF** pins *FPF<sub>PK</sub>* in the **Journalist** client, in the **Source** client and in the **Server** code.

 * **Newsroom**:

     | Operation | Description |
     |---|---|
     | *NR<sub>SK</sub> = Gen()* | Newsroom generates a random private key with similar security of the FPF one |
     | *NR<sub>PK</sub> = GetPub(<sub>SK</sub>)* | Derive the corresponding public key |
     | *sig<sup>FPF</sup>(NR<sub>PK</sub>) = Sign(FPF<sub>SK</sub>, NR<sub>PK</sub>)* | Newsroom sends a CSR or the public key to FPF; FPF validates manually/physically before signing |

    **Newsroom** pins *NR<sub>PK</sub>* and *sig<sup>FPF</sup>(NR<sub>PK</sub>)* in the **Server** during initial server setup.

 * **Journalist [0-i]**:

     | Operation | Description |
     |---|---|
     | *J<sub>SK</sub> = Gen()* | Journalist generates the long-term signing key randomly |
     | *J<sub>PK</sub> = GetPub(J<sub>SK</sub>)* | Derive the corresponding public key | 
     | *sig<sup>NR</sup>(J<sub>PK</sub>) = Sign(NR<sub>SK</sub>, J<sub>PK</sub>)* | Journalist sends a CSR or the public key to the Newsroom admin/managers for signing |
     | *JC<sub>SK</sub> = Gen()* | Journalist generate the long-term message-fetching key randomly (TODO: this key could be rotated often) |
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

### Source submission to Journalist
 1. *Source* fetches *NR<sub>PK</sub>*, *sig<sup>FPF</sup>(NR<sub>PK</sub>)*
 2. *Source* checks *Verify(FPF<sub>PK</sub>,sig<sup>FPF</sup>(NR<sub>PK</sub>)) == true*, since FPF<sub>PK</sub> is pinned in the Source client
 3. For every *Journalist* (i) in *Newsroom*
     - *Source* fetches *<sup>i</sup>J<sub>PK</sub>*, *<sup>i</sup>sig<sup>NR</sup>(<sup>i</sup>J<sub>PK</sub>)*, *<sup>i</sup>JC<sub>PK</sub>*, *<sup>i</sup>sig<sup>iJ</sup>(<sup>i</sup>JC<sub>PK</sub>)*
     - *Source* checks *Verify(NR<sub>PK</sub>,<sup>i</sup>sig<sup>NR</sup>(<sup>i</sup>J<sub>PK</sub>)) == true*
     - *Source* checks *Verify(<sup>i</sup>J<sub>PK</sub>,<sup>i</sup>sig<sup>iJ</sup>(<sup>i</sup>JC<sub>PK</sub>)) == true*
     - *Source* fetches *<sup>ik</sup>JE<sub>PK</sub>*, *<sup>ik</sup>sig<sup>iJ</sup>(<sup>ik</sup>JE<sub>PK</sub>)* (k is random from the pool of non used, non expired, *Journalist* ephemeral keys)
     - *Source* checks *Verify(<sup>i</sup>J<sub>PK</sub>,<sup>ik</sup>sig<sup>iJ</sup>(<sup>ik</sup>JE<sub>PK</sub>)) == true*
 4. *Source* generates the unique passphrase randomly *PW = G()* (the only state that identifies the specific *Source*)
 5. *Source* derives *S<sub>SK</sub> = G(KDF(encryption_salt + PW))*, *S<sub>PK</sub> = GetPub(S<sub>SK</sub>)*
 6. *Source* derives *SC<sub>SK</sub> = G(KDF(fetching_salt + PW))*, *SC<sub>PK</sub> = GetPub(SC<sub>SK</sub>)*
 7. *Source* splits any attachment in parts of size `commons.CHUNKS`. Any chunk smaller is padded to `commons.CHUNKS` size.
 8. For every *Chunk*, *<sup>m</sup>u*
    - *Source* generate a random key *<sup>m</sup>s = G()*
    - *Source* encrypts *<sup>m</sup>u* using *<sup>m</sup>s*: *<sup>m</sup>f = E(<sup>m</sup>s, <sup>m</sup>u)*
    - *Source* uploads *<sup>m</sup>f* to *Server* and which returns a random token <sup>m</sup>t (`file_id`)
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


### Server message id fetching procol
 1. *Server* generates per-request, ephemeral secret key *RE<sub>SK</sub> = Gen()*
 2. For evey entry *<sup>i</sup>mid* -> *<sup>i</sup>ME<sub>PK</sub>*, *<sup>i</sup>mgdh* (`message_id` -> (`message_gdh`, `message_public_key`)):
     - *Server* calculates *<sup>i</sup>kmid = DH(RE<sub>SK</sub>,<sup>i</sup>mgdh)*
     - *Server* calculates *<sup>i</sup>pmgdh = DH(RE<sub>SK</sub>,<sup>i</sup>ME<sub>PK</sub>)*
     - *Server* encrypts *<sup>i</sup>mid* using *<sup>i</sup>kmid*: *<sup>i</sup>enc_mid = Enc(<sup>i</sup>kmid, <sup>i</sup>mid)*
  3. *Server* generates *j = [`commons.MAX_MESSAGES - i`]* random decoys *<sup>[0-j]</sup>decoy_pmgdh* and *<sup>[0-j]</sup>decoy_enc_mid*
  4. *Server* returns a shuffled list of `commons.MAX_MESSAGES` (*i+j*) tuples of *(<sup>[0-i]</sup>pmgdh,<sup>[0-i]</sup>enc_mid) U (<sup>[0-j]</sup>decoy_pmgdh,<sup>[0-j]</sup>enc_mid)*


### Journalist message id fetching protocol
  1. *Source* derives *SC<sub>SK</sub> = G(KDF(fetching_salt + PW))*
  2. *Source* fetches *(<sup>[0-n]</sup>pmgdh,<sup>[0-n]</sup>enc_mid)* from *Server* (`n=commons.MAX_MESSAGES`)
  3. For every *(<sup>n</sup>pmgdh,<sup>n</sup>enc_mid)*:
     - *Source* calculates *<sup>n</sup>kmid = DH(<sup>n</sup>pmgdh,SC<sub>SK</sub>)*
     - *Source* attempts to decrypt *<sup>n</sup>mid = Dec(<sup>n</sup>kmid,<sup>n</sup>enc_mid)*
     - If decryption succeeds, save *<sup>n</sup>mid*

### Source message id fetching protocol

  1. *Journalist* fetches *(<sup>[0-n]</sup>pmgdh,<sup>[0-n]</sup>enc_mid)* from *Server* (`n=commons.MAX_MESSAGES`)
  2. For every *(<sup>n</sup>pmgdh,<sup>n</sup>enc_mid)*:
     - *Journalist* calculates *<sup>n</sup>kmid = DH(<sup>n</sup>pmgdh,JC<sub>SK</sub>)*
     - *Journalist* attempts to decrypt *<sup>n</sup>mid = Dec(<sup>n</sup>kmid,<sup>n</sup>enc_mid)*
     - If decryption succeeds, save *<sup>n</sup>mid*


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
 4. *Journalist* pads the text to a fixed size: *mp = Pad(message, metadata)*
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
*Source* replies work the exact same way as a first submission, except the source is already known to the *Journalist*.

### Flow Chart

![chart](https://github.com/lsd-cat/securedrop-poc/blob/main/imgs/sd_schema.png?raw=true)

## Server endpoints

All endpoints do not require authentication or sessions. The only data store is Redis and is schema-less. Encrypted file chinks are stored to disk. No database bootstrap is required.

### /journalists

**Legend**:

| JSON Name | Value |
|---|---|
|`count` | Number of returned enrolled *Journalists* |
|`journalist_key` | *base64(J<sub>PK</sub>)* |
|`journalist_sig` | *base64(sig<sup>NR</sup>(J<sub>PK</sub>))* |
|`journalist_fetching_key` | *base64(JC<sub>PK</sub>)* |
|`journalist_fetching_sig` | *base64(sig<sup>J</sup>(JC<sub>PK</sub>))* |
|`journalist_uid` | *hex(Hash(J<sub>PK</sub>))* |

#### POST
Adds *Newsroom* signed *Journalist* to the *Server*.
```
curl -X POST -H "Content-Type: application/json" "http://127.0.0.1:5000/journalists" --data
{
    "journalist_key": <journalist_key>,
    "journalist_sig": <journalist_sig>,
    "journalist_fetching_key": <journalist_fetching_key>,
    "journalist_fetching_sig": <journalist_fetching_sig>
}
```
```
200 OK
```

The server checks for proper signature using *NR<sub>PK</sub>*. If both signatures are valid, the request fields are added to the `journalists` Redis *set*.

#### GET
Gets the journalists enrolled in *Newsroom* and published in the *Server*.
The *Journalist* UID is a hex encoded hash of the Journalist long-term signing key.

```
curl -X GET "http://127.0.0.1:5000/journalists"
```
```
200 OK
{
  "count": <count>,
  "journalists": [
    {
      "journalist_fetching_key": <journalist_fetching_key>,
      "journalist_fetching_sig": <journalist_fetching_sig>,
      "journalist_key": <journalist_key>,
      "journalist_sig": <journalist_sig>,
      "journalist_uid": <journalist_uid>
    },
    ...
  ],
  "status": "OK"
}
```

At this point *Source* must have a verified *NR<sub>PK</sub>* and must verify both *sig<sub>J</sub>* and *sig<sub>JC</sub>*.

#### DELETE (TODO)
*Not implemented yet. A Newsroom must be able to remove Journalists.*

### /ephemeral_keys

**Legend**:

| JSON Name | Value |
|---|---|
|`count` | Number of returned ephemeral keys. It should match the number of *Journalists*. If it does not, a specific *Journalist* bucket might be out of keys. |
|`ephemeral_key` | *base64(JE<sub>PK</sub>)* |
|`ephemeral_sig` | *base64(sig<sup>J</sup>(JE<sub>PK</sub>))* |
|`journalist_uid` | *hex(Hash(J<sub>PK</sub>))* |


#### POST
Adds *n* *Journalist* signed ephemeral key agreement keys to Server.
The keys are stored is a Redis *set* specific per *Journalist*, which key is `journalist:<journalist_uid>`. In the demo implementation, the number of ephemeral keys to generate and upload each time is `commons.ONETIMEKEYS`. 

```
curl -X POST -H "Content-Type: application/json" "http://127.0.0.1:5000/ephemeral_keys" --data
{
  "journalist_uid": <journalist_uid>,
  "ephemeral_keys": [
    {
      "ephemeral_key": <ephemeral_key>,  
      "epheneral_sig": <ephemeral_sig>
    },
    ...
  ]
}
```
```
200 OK
{
  "status": "OK"
}
```
#### GET
The server pops a random ephemeral_key from every enrolled journalist bucket and returns it. The `pop` operation effectively removes the returned keys from the corresponding *Journalist* bucket.
```
curl -X GET http://127.0.0.1:5000/ephemeral_keys
```
```
200 OK
{
  "count": <count>,
  "ephemeral_keys": [
    {
      "ephemeral_key": <ephemeral_key>,
      "ephemeral_sig": <ephemeral_sig>,
      "journalist_uid": <journalist_uid>
    },
    ...
  ],
  "status": "OK"
}
```
At this point *Source* must have verified all the J<sup>[0-i]</sup><sub>PK</sub>*  and can thus verify all the corresponding *sig<sup>[0-n]</sup><sub>JE</sub>*.

#### DELETE (TODO)
*Not implemented yet. A Journalist shall be able to revoke keys from the server.*

### /fetch

**Legend**:

| JSON Name | Value |
|---|---|
|`count` | Number of returned potential messages. Must always be greater than the number of messages on the server. Equal to `commons.MAX_MESSAGES` so that it should always be the same for every request to prevent leaking the number of messages on the server. |
|`messages` | *(base64(pmgdh),base64(enc_mid))* |

#### GET
The server sends all the mixed group Diffie Hellman shares, plus the encrypted message id of the corresponding messsage. *gdh* and *enc* are paired in couples.

```
curl -X GET http://127.0.0.1:5000/fetch
```
```
200 OK
{
  "count": <commons.MAX_MESSAGES>,
  "messages": [
     {
       "gdh": <share_for_group_DH1>,
       "enc": <encrypted_message_id1>,
     },
     {
       "gdh": <share_for_group_DH2>,
       "enc": <encrypted_message_id2>,
     }
    ...
    <commons.MAX_MESSAGES>
    ],
  "status": "OK"
}
```
### /message/[message_id]

**Legend**:

| JSON Name | Value |
|---|---|
| `message_id` | Randomly generated unique, per message id. |
|`message_ciphertext` | *base64(Enc(k, m))* where *k* is a key agreement calculated key. The key agreement keys depend on the parties encrypting/decrypting the message. |
|`message_public_key` | *base64(ME<sub>PK</sub>)* |
|`message_gdh` | *base64(ME<sub>SK</sub>,SC/JC<sub>PK</sub>)* |

#### POST
```
curl -X POST -H "Content_Type: application/json" http://127.0.0.1:5000/message --data
{
  "message_ciphertext": <message_ciphertext>,
  "message_public_key": <message_public_key>,
  "message_gdh": <message_gdhe>
}
```
```
200 OK
{
  "status": "OK"
}
```

Note that `message_id` is not returned upon submission, so that the sending party cannot delete or fetch it unless they maliciously craft the `message_gdh` for themselves, but at that point it would never be delivered to any other party.

#### GET
`message_public_key` is necessary for completing the key agreement protocol and obtaining the shared symmetric ey to decrypt the message. `message_public_key`, is ephemeral, unique per message, and has no links to anything else.

```
curl -X GET http://127.0.0.1:5000/message/<message_id>
```
```
200 OK
{
  "message": {
    "message_ciphertext": <message_ciphertext>,
    "message_public_key": <message_public_key>
  },
  "status": "OK"
}
```

#### DELETE

```
curl -X DELETE http://127.0.0.1:5000/message/<message_id>
```
```
200 OK
{
  "status": "OK"
}
```

### /file/[file_id]
Slicing and encrypting is up to the *Source* client. The server cannot enforce encryption, but it can enforce equal chunk size (TODO: not implemented).

**Legend**:

| JSON Name | Value |
|---|---|
|`file_id` | Unique, randomly generated per upload id. Files are sliced, paded and encrypted to a fixed size so that all files looks equal and there are no metadata, however that is up to the uploading client. |
| `raw_encrypted_file_content` | Raw bytes composing the encrypted file object. |

#### POST
The `file_id` is secret, meaning that any parties with knowledge of it can either download the encrypted chunk or delete it. In production, it could be possible to set `commons.UPLOADS` to a FUSE filesystem without timestamps.

```
curl -X POST http://127.0.0.1:5000/file -F <path_to_encrypted_chunk>
```
```
200 OK
{
  "file_id": <file_id>,
  "status": "OK"
}
```

#### GET
The server will return either the raw encrypted content or a `404` status code.
```
curl -X GET http://127.0.0.1:5000/file/<message_id>
```
```
200 OK
<raw_encrypted_file_content>
```
#### DELETE
A delete request deletes both the entry on the database and the encrypted chunk on the server storage.
```
curl -X DELETE http://127.0.0.1:5000/file/<file_id>
```
```
200 OK
{
  "status": "OK"
}
```

## Limitations
### Crypto
The cryptographic protocol needs to be audited.
  
### Behavioral analysis
While there are no accounts, and all messages are equal, the server could detect if it is interacting with a source or a journalist by observing the API request pattern. While all the clients, both source and journalist, would go through the Tor network and look the same from an HTTP perspective, they might perform different actions, such as ephemeral keys upload. A further fingerprinting mechanism could be, for instance, measuring how much time any client takes to fetch messages. It is up to the clients to mitigate this, sending decoy traffic and introducing randomness between requests.

### Ephemeral key exhaustion
As a known problem in this kind of protocols, what happens when the ephemeral keys of a journalist are exhausted due to either malicious intent or infrequent upload by the journalist?

### Ephemeral key reuse (malicious server)
While it is not currently implemented, ephemeral keys should include a short (30/60 days) expiation date along with their PK signature. Journalists can routinely query the server for ephemeral keys and heuristically test if the server is being dishonest as well. They can also check during decryption as well and see if an already used key has worked: in that case the server is malicious as well.

### Decoy traffic
This schema is very open to decoy traffic. Since all messages and all submissions are equal from a server perspective, as well as all fetching operations, and there is no state or cookies involved between request, any party on the internet could produce decoy traffic on any istance. Newsrooms, journalists or even FPF could produce all the required traffic just from a single machine.

### Message retention
The server cannot keep too many messages with the current configuration, as more than a few thousands at a time would be too much to compute reasonable time. Messages needs either to be deleted upon read or to automatically expiry (after a few days maybe). In case of expiration, that expiration should have a degree of randomness, otherwise the expiration time would be the same of a submission date in the context of minimizing metadata.

### Denial of service
In having no accounts, it might be easy to flood the service of unwanted messages or of fetching requests that would be heavy on the server CPU. Depending on the individual *Newsroom* previous issues and threat model, classic rate limiting such as proof of work or captchas (even though we truly dislike them) could mitigate the issue.

### Minimize logging
To minimize logging, ans mix traffic better, it could be reasonable to make all endpoints the same and POST only and remove all GET parameters. An alternative solution could be to implement the full protocol over WebSockets.

### Revocation
Revocation is a spicy topic. For ephemeral keys, we expect expiration to be generally enough. For long-term keys, including eventual journalist de-enrollment or newsroom key rotation something along the standard has to be implemented, requiring eventually more infrastructure. For example, FPF could routinely publish a revocation list and host the Newsroom ones as well; however that must work even without FPF direct involvement. A good, already deployed, protocol for serving the revocation would be OCSP stapling served back directly by the SecureDrop server, so that clients (both sources and journalists) do not have to do external requests. Otherwise we could find a way to (ab)use the current internet revocation infrastructure and build on top of that.

### More hardening
The protocol can be hardened further in specific parts: rotating fetching keys regularly on the journalist side, adding a short expiration (~30 days) to ephemeral keys so that they are guaranteed to rotate even in case of malicious servers, having "submit" only sources that do not save the passphrase and are not reachable after first contact. These details are left for internal team evaluation and production implementation constraints.