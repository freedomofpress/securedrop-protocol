---
geometry: margin=2cm
---

# Next-Gen SecureDrop Research

## Selling points
 * All messages are equal
 * There are no accounts
 * Everything is end to end encrypted with one time symmetric keys
 * Source to journalist key agreement has forward secrecy
 * Zero explicit metadata on the server; there are implicit metadata such as access patterns to the API
 * Key isolation: each key is used only for a cryptographic purpose: signing, encryption, NIZK

## Config
In `commons.py` there are the following configuration values which are global for all components, even though of course not everybody need all of them.

| Variable | Value | Components | Description |
|---|---|---|---|
| `SERVER` | `127.0.0.1:5000` | source, journalist | The URL the Flask server listens on; used by both the journalist and the source clients. |
| `DIR` | `keys/` | server, source, journalist | The folder where everybody will load the keys from. There is no separation for demo simplicity of course in an actual implementation, everybody will only have their keys and the required public one to ensure the trust chain. |
| `UPLOADS` | `files/` | server | The folder where the Flask server will store uploaded files. |
| `DOWNLOADS` | `downloads/` | journalist | The folder where submission attachments will be saved. |
| `JOURNALISTS` | `10` | server, source |  How many journalists do we create and enroll. In general, this is realistic, in current SecureDrop usage it is way less. For demo purposes everybody knows it, in a real scenario it would not be needed. |
| `ONETIMEKEYS` | `30` | journalist | How many ephemeral keys each journalist create, sign and uploads when required. |
| `CURVE` | `NIST384p` | server, source, journalist | The curve for all elliptic curve operations. It must be imported first from the python-ecdsa library. Ed25519 and Ed448, although supported by the lib, are not fully implemented. |
| `CHALLENGES` | `500` | server | How may challenges the server sends to each party when they try to fetch messages. This basically must be more than the messages in the database, otherwise we need to develop a mechanism to group challenges adding some bits of metadata. |
| `CHALLENGES_TTL` | `30` | server | The time windows, in seconds, that a journalist or a source has to send the responses to a given `challenge_id` |
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

Next, you have to upload `file_tokens` and their signature by impersonating any journalist (using them is automatic for all journalists, `file_tokens` are shared between them):
```
python3 journalist.py -j 7 -a upload_file_tokens
```

After this, sources may start sending in submissions.

You can also generate call/caller graphs by running `make docs`.

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
usage: journalist.py [-h] -j [0, 9] [-a {upload_keys,upload_file_tokens,fetch,read,reply,delete}] [-i ID] [-m MESSAGE]

options:
  -h, --help            show this help message and exit
  -j [0, 9], --journalist [0, 9]
                        Journalist number
  -a {upload_keys,upload_file_tokens,fetch,read,reply,delete}, --action {upload_keys,upload_file_tokens,fetch,read,reply,delete}
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

## Threat model
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
     * *JC<sub>SK</sub>*: Long term Journalist zero-knowledge private key
     * *JC<sub>PK</sub>*: Long term Journalist zero-knowledge public key
     * *JE<sub>SK</sub>*: Ephemeral (per-message) key agreement private key
     * *JE<sub>PK</sub>*: Ephemeral (per-message) key agreement public key
 * **Sources**:
     * *PW*: Secret passphrase
     * *S<sub>SK</sub>*: Long term Source key agreement private key
     * *S<sub>PK</sub>*: Long term Source key agreement public key
     * *SC<sub>SK</sub>*: Long term Source zero-knowledge private key
     * *SC<sub>PK</sub>*: Long term Source zero-knowledge public key
 * **Messages**:
     * *ME<sub>SK</sub>*: Ephemeral per-message key agreement private key
     * *ME<sub>PK</sub>*: Ephemeral per-message key agreement public key
 * **Server**:
     * *RE<sub>SK</sub>*: Ephemeral Server, per-challenge zero-knowledge private key 
     * *RE<sub>PK</sub>*: Ephemeral Server, per-challenge zero-knowledge public key
     * *DE<sup>n</sup><sub>PK</sub>*: Per-request, ephemeral decoy public key

## Functions
| Formula | Description |
|---|---|
| *c = E(k, m)* | Encrypt message *m* to ciphertext *c* using symmetric key *k* |
| *m = D(k, c)* | Decrypt ciphertext *c* to message *m* using symmetric key *k* |
| *h = H(m)* | Hash message *m* to hash *h* |
| *k = KDF(m)* | Derive a key *k* from message *m* |
| *SK, PK = G(s)* | Generate a private key *SK* public key *PK* pair using seed *s*; if seed is empty generation is securely random |
| *sig = Sig(SK, m)* | Create signature *sig* using *SK* as the signer key and *m* as the signed message |
| *k = DH(A<sub>SK</sub>, B<sub>PK</sub>) == DH(A<sub>PK</sub>, B<sub>SK</sub>)* | Generate shared key *k* using a key agreement primitive |

## Initial trust chain setup

 * **FPF**:

     | Operation | Description |
     |---|---|
     |*FPF<sub>SK</sub>, FPF<sub>PK</sub> = G()* | FPF generates a random key-pair (we might add HSM requirements, or certificate style PKI, ie: self signing some attributes)|

    **FPF** pins *FPF<sub>PK</sub>* in the **Journalist** client, in the **Source** client and in the **Server** code.

 * **Newsroom**:

     | Operation | Description |
     |---|---|
     | *NR<sub>SK</sub>, NR<sub>PK</sub> = G()* | Newsroom generates a random key-pair with similar security of the FPF one |
     | *sig<sub>NR</sub> = Sig(FPF<sub>SK</sub>, NR<sub>PK</sub>)* | Newsroom sends a CSR or the public key to FPF for signing |

    **Newsroom** pins *NR<sub>PK</sub>* in the **Server** during initial server setup.

 * **Journalist [0-i]**:

     | Operation | Description |
     |---|---|
     | *J<sub>SK</sub>, J<sub>PK</sub> = G()* | Journalist generates the long-term signing key randomly |
     | *sig<sub>J</sub> = Sig(NR<sub>SK</sub>, J<sub>PK</sub>)* | Journalist sends a CSR or the public key to the Newsroom admin/managers for signing |
     | *JC<sub>SK</sub>, JC<sub>PK</sub> = G()* | Journalist generate the long-term challenge key randomly |
     | *sig<sub>JC</sub> = Sig(J<sub>SK</sub>, JC<sub>PK</sub>)* | Journalist signs the long-term challenge key with the long-term signing key |
     | *JE<sup>[0-n]</sup><sub>SK</sub>, JE<sup>[0-n]</sup><sub>PK</sub> = G()* | Journalist generates a number *n* of ephemeral key agreement keys randomly |
     | *sig<sup>[0-n]</sup><sub>JE</sub> = Sig(J<sub>SK</sub>, JE<sup>[0-n]</sup><sub>PK</sub>)* | Journalist individually signs the ephemeral key agreement keys (TODO: add key hard expiration) |

    **Journalist** sends *J<sub>PK</sub>*, *sig<sub>J</sub>*, *JE<sup>[0-n]</sup><sub>PK</sub>* and *sig<sup>[0-n]</sup><sub>JE</sub>* to **Server** which verifies and publishes them.

 * **Source [0-j]**:

     | Operation | Description |
     |---|---|
     | *PW* = G() | Source generates a secure passphrase which is the only state available to clients|
     | *S<sub>SK</sub>, S<sub>PK</sub> = G(KDF(encryption_salt \|\| PW))* | Source deterministically generates the long-term key agreement key-pair using a specific hard-coded salt |
     | *SC<sub>SK</sub>, SC<sub>PK</sub> = G(KDF(challenge_salt \|\| PW))* | Source deterministically generates the long-term challenge key-pair using a specific hard-coded salt |

    **Source** does not need to publish anything until the first submission is sent.

## Messaging protocol overview
Only a source can initiate a conversation; there are no other choices as sources are effectively unknown until they initiate contact in the first place.

### Source to Journalist
 1. *Source* fetches *NR<sub>PK</sub>*, *sig<sub>NR*
 2. *Source* verifies *sig<sub>NR* using *FPF<sub>PK</sub>*
 3. *For every *Journalist* (i) in *Newsroom*
     - *Source* fetches *J<sup>i</sup><sub>PK</sub>*, *sig<sup>i</sup><sub>J</sub>*, *JC<sup>i</sup><sub>PK</sub>* and *sig<sup>i</sup><sub>JC</sub>*
     - *Source* verifies *sig<sup>i</sup><sub>J</sub>* and *sig<sup>i</sup><sub>JC</sub>* using *NR<sub>PK</sub>*
     - *Source* fetches *JE<sup>ik</sup><sub>PK</sub>* and *sig<sup>ik</sup><sub>JE</sub>* (k is random from the pool of non used, non expired, *Journalist* ephemeral keys)
     - *Source* verifies *sig<sup>ik</sup><sub>JE</sub>* using *JE<sub>PK</sub>*
 4. *Source* generates the unique passphrase randomly *PW = G()* (the only state that identify the specific *Source*)
 5. *Source* derives *S<sub>PK</sub>, S<sub>SK</sub> = G(KDF(encryption_salt + PW))*
 6. *Source* derives *SC<sub>PK</sub>, SC<sub>SK</sub> = G(KDF(challenge_salt + PW))*
 7. *Source* splits any attachment in parts of size `commons.CHUNKS`. Any chunk smaller is padded to `commons.CHUNKS` size.
 8. For every *Chunk*, *u*
    - *Source* generate a random key *s<sup>m</sup> = G()*
    - *Source* encrypts *u<sup>m</sup>* with *s<sup>m</sup>*, *f<sup>m</sup> = E(s<sup>m</sup>, u<sup>m</sup>)*
    - *Source* uploads *f<sup>m</sup>* to *Server* and obtains a `file_id`
 9. *Source* adds metadata, *S<sub>PK</sub> and SC<sub>PK</sub> to message *m*.
 10. *Source* adds attachment info to message *m* (all the *s* keys and all the `file_id`)
 11. *Source* pads the resulting text to a fixed size, *mp* (message, metadata, attachments, padding)
 12. For every *Journalist* (i) in *Newsroom* 
     - *Source* generates *ME<sup>i</sup><sub>PK</sub>, ME<sub>PK</sub> = G()* (random, per message keys)
     - *Source* calculates the shared encryption key using a key agreement protocol *k<sup>ik</sup> = DH(ME<sub>SK</sub>, JE<sup>ik</sup><sub>PK</sub>)*
     - *Source* encrypts *mp* using *k<sup>ik*, *c<sup>i</sup> = E(k<sup>i</sup>, mp)*
     - *Source* calculates the message_challenge (`message_challenge`) *mc = DH(ME<sub>SK</sub>, JC<sup>ik</sup><sub>PK</sub>)*
     - *Source* sends *c<sup>i</sup>*, *ME<sup>i</sup><sub>PK</sub>* and *mc<sup>i</sup>* to server
     - *Server* generates a random `message_id` *i* and stores `message:i` -> *c<sup>i</sup>*, *ME<sup>i</sup><sub>PK</sub>*, *mc*

### Server challenge generation
 1. *Server* fetches all `message_id`, `message_challenge` and `message_public_key` from Redis
 2. *Server* generates a per-challenge, ephemeral key-pair *RE<sub>SK</sub>, RE<sub>PK</sub> = G()*
 3. *Server* generates a unique, random challenge id *d*
 4. *Server* stores in redis `challenge_id:d` -> *RE<sub>SK</sub>* with TTL of `commons.CHALLENGES_TTL`
 5. For every message fetched from Redis, the *Server* mix the per-challenge key *RE<sub>SK</sub>* to the message_challenge *mc* resulting in *chall<sup>i</sup> = DH(DH(ME<sub>SK</sub>, JC<sup>ik</sup><sub>PK</sub>), RE<sub>SK</sub>)*
 6. If the messages in Redis are less then `commons.CHALLENGES`, the *Server* generates *N* decoy challenges *DE<sup>n</sup><sub>SK</sub>, DE<sup>n</sup><sub>PK</sub> = G()*
 7. The *Server* returns the real challenges and the decoy challenges to the client, being it a *Source* or a *Journalist*, attaching also the `challenge_id`

### Journalist fetch
 1. *Journalist* makes a request to the *Server* and fetch all the challenges.
 2. *Journalist* calculates the inverse of their challenge private key *inv<sub>JC</sub> = Inv(JC<sub>SK</sub>)*
 3. For every challenge, the *Journalist* calculates a response by removing their Diffie-Hellman share obtaining the following *response = DH(chall<sup>i</sup>, inv<sub>JC</sub>)*
 4. *Journalist* returns all the responses to the *Server*, attaching the `challenge_id` that came from the *Server*
 5. *Server* fetch from Redis the `challenge_id` containing *RE<sub>SK</sub>*
 6. *Server* calculates the inverse of per-challenge key *inv<sub>RE</sub> = Inv(RE<sub>SK</sub>)* 
 7. For every challenge, the *Server*: 
     - removes their Diffie-Hellman share obtaining the following *proof = DH(response<sup>i</sup>, inv<sub>RE</sub>)*
     - verify that the *proof* is equal to *ME<sup>i</sup><sub>PK</sub>*
     - if a *proof* is correct, returns to the *Journalist* the related `message_id` from Redis

### Journalist read
 1. *Journalist* fetches from *Server* `message_ciphertext`, *c*, `message_public_key`, *ME<sub>PK</sub>* using `message_id`
 2. *Journalist* for every unused ephemeral key *JE<sup>k</sup><sub>SK</sub>*
     - *Journalist* calculates a tentative shared encryption key using the key agreemenet protocol *k<sup>k</sup> = DH(JE<sup>k</sup><sub>SK</sub>, ME<sub>PK</sub>)*
     - *Journalist* tries to decrypt *mp = D(k<sup>k</sup>, c)*
     - *Journalist* verifies that *mp* decrypted succesfully, if yes exits from the loop
 3. *Journalist* removes padding from *mp* and parse message *m*, metadata, and attachment details
 4. *Journalist* for every attachment *Chunk*
     - *Journalist* fetches the encrypted *Chunk* *f<sup>m</sup>* from *Server*, mapping the source supplied `file_id` to `file_name` that is needed to access the file
     - *Journalist* decrypts *f<sup>m</sup>* using *s<sup>m</sup>* *u = D(s<sup>m</sup>, f<sup>m</sup>)*
     - *Journalist* join *Chunks* according to metadata and saves back the original files
 5. *Journalist* reads the message *m*
 6. *Journalist* may delete the message from the *Server* using `message_id`

### Journalist reply
 1. *Journalist* has plaintext *m*, which contains also *S<sub>PK</sub>* and SC<sub>PK</sub>
 2. *Journalist* generates *ME<sup>PK</sup>, ME<sup>PK</sup> = G()* (random, per message keys)
 3. *Journalist* calculate the shared encryption key using a key agreement protocol *k = DH(ME<sub>SK</sub>, S<sub>PK</sub>)*
 4. *Journalist* adds metadata to message *m2*.
 5. *Journalist* pads the resulting text to a fixed size, *m2p* (message, metadata, padding)
 6. *Journalist* encrypts *mp* using *k*, *c = E(k, m2p)*
 7. *Journalist* calculates the message_challenge (`message_challenge`) *mc = DH(ME<sub>SK</sub>, SC<sub>PK</sub>)*
 8. *Journalist* sends *c*, *ME<sub>PK</sub>* and *m2c* to server
 9. *Server* generates a random `message_id` *i* and stores `message:i` -> *c*, *ME<sub>PK</sub>*, *mc*

### Source fetch
 1. *Source* makes a request to the *Server* and fetch all the challenges.
 2. *Source* calculates the inverse of their challenge private key *inv<sub>SC</sub> = Inv(SC<sub>SK</sub>)*
 3. For every challenge, the *Source* calculates a response by removing their Diffie-Hellman share obtaining the following *response = DH(chall<sup>i</sup>, inv<sub>SC</sub>)*
 4. *Source* returns all the responses to the *Server*, attaching the `challenge_id` that came from the *Server*
 5. *Server* fetch from Redis the `challenge_id` containing *RE<sub>SK</sub>*
 6. *Server* calculates the inverse of per-challenge key *inv<sub>RE</sub> = Inv(RE<sub>SK</sub>)* 
 7. For every challenge, the *Server*: 
     - removes their Diffie-Hellman share obtaining the following *proof = DH(response<sup>i</sup>, inv<sub>RE</sub>)*
     - verify that the *proof* is equal to *ME<sup>i</sup><sub>PK</sub>*
     - if a *proof* is correct, returns to the *Source* the related `message_id` from Redis

### Source read
 1. *Source* fetches from *Server* `message_ciphertext`, *c*, `message_public_key`, *ME<sub>PK</sub>* using `message_id`
 2. *Source* derives *S<sub>PK</sub>, S<sub>SK</sub> = G(KDF(encryption_salt + PW))*
 3. *Source* calculate the shared encryption key using a key agreement protocol *k = DH(S<sub>SK</sub>, ME<sub>PK</sub>)*
 4. *Source* *mp = D(k<sup>k</sup>, c)*
 5. *Source* reads the metadata and the message *m*

### Source reply
*Source* replies work the exact same way as a first submission, except the source is already known to the *Journalist*.

### Flow Charts

![chart1](https://github.com/lsd-cat/securedrop-poc/blob/main/imgs/sd2-Schema%20-%20Souce%20Submission.png?raw=true)  
![chart2](https://github.com/lsd-cat/securedrop-poc/blob/main/imgs/sd2-Schema%20-%20Journal%20Reply.png?raw=true)

## Server endpoints

All endpoints do not require authentication or sessions. The only data store is Redis and is schema-less. Encrypted file chinks are stored to disk. No database bootstrap is required.

### /journalists

**Legend**:

| JSON Name | Value |
|---|---|
|`count` | Number of returned enrolled *Journalists*. |
|`journalist_key` | *base64(J<sub>PK</sub>)* |
|`journalist_sig` | *base64(sig<sub>J</sub>)* |
|`journalist_chal_key` | *base64(JC<sub>PK</sub>)* |
|`journalist_chal_sig` | *base64(sig<sub>JC</sub>)* |
|`journalist_uid` | *hex(H(J<sub>PK</sub>))* |

#### POST
Adds *Newsroom* signed *Journalist* to the *Server*.
```
curl -X POST -H "Content-Type: application/json" "http://127.0.0.1:5000/journalists" --data
{
    "journalist_key": <journalist_key>,
    "journalist_sig": <journalist_sig>,
    "journalist_chal_key": <journalist_chal_key>,
    "journalist_chal_sig": <journalist_chal_sig>
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
      "journalist_chal_key": <journalist_chal_key>,
      "journalist_chal_sig": <journalist_chal_sig>,
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
|`ephemeral_sig` | *base64(sig<sub>JE</sub>)* |
|`journalist_uid` | *hex(H(J<sub>PK</sub>))* |


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

```
At this point *Source* must have verified all the J<sup>[0-i]</sup><sub>PK</sub>*  and can thus verify all the corresponding *sig<sup>[0-n]</sup><sub>JE</sub>*.

### /file_tokens

| JSON Name | Value |
|---|---|
|`file_tokens` | String of json encoded list of `[file_id, file_name]` pairs, both of which are `token_hex(32)` values. Used by the server to tell uploading parties the `file_id`, which only journalists can then map to the `file_name` that is used to access and delete files |
|`sig` | *base64(sig<sub>file_tokens</sub>)* |
|`journalist_uid` | *hex(H(J<sub>PK</sub>))* |

#### POST
Adds *n* *Journalist* signed file token pairs to the Server.
The token pairs are stored in a Redis *set*, the key of which is `file_tokens`. In the demo implementation, the number of file tokens generated and uploaded each time is `commons.ONETIMEKEYS * 10`.

```
curl -X POST -H "Content-Type: application/json" "http://127.0.0.1:5000/file_tokens" --data
{
  "file_tokens": <file_tokens>,
  "sig": <sig>,
  "journalist_uid": <journalist_uid>
}
```
```
200 OK
{
  "status": "OK"
}
```

#### DELETE (TODO)
*Not implemented yet. A Journalist shall be able to revoke keys from the server.*
### /challenge/[challenge_id]

**Legend**:

| JSON Name | Value |
|---|---|
|`count` (GET) | Number of returned message challenges. Must always be greater than the number of messages on the server. Equal to `commons.CHALLENGES` so that it should always be the same for every request to prevent leaking the number of messages on the server. |
|`count` (POST) | Number of returned `message_id` values, which is the number of message for the requesting source or journalist. |
|`challenge_id` | Unique, random-generate id of the challenge that needs to be supplied when sending the challenges responses. |
|`message_challenges` | Array of *TODO formula here* |
|`message_challenges_responses` | Array of *TODO formula here* |
|`message_id` | Random, secret identifier of a given encrypted message on the server. The ID is the only thing needed to fetch or delete a message. |

#### GET
The server send some challenges and a `challenge_id`. Order is not important.
```
curl -X GET http://127.0.0.1:5000/challenge
```
```
200 OK
{
  "count": <commons.CHALLENGES>,
  "challenge_id": <challege_id>,
  "message_challenges": [
    <challenge_1>,
    <challenge_2>,
    ...
    <challenge_commons.CHALLENGES>
    ],
  "status": "OK"
}
```
#### POST
`challenge_id` will expire according to `commons.CHALLENGES_TTL` value; after that a `400` error code will be returned. If no challenges are solved correctly using the corresponding challenge key, it means that there are no messages for that user and a `404` error code is returned.
Order is not important.

```
curl -X POST -H "Content-Type: application/json" http://127.0.0.1:5000/challenge/<challenge_id> --data
{
  "message_challenges_responses": [
    <challenge_response_1>,
    <challenge_response_2>,
    ...
    <challenge_response_commons.CHALLENGES>
  ]
}
```
```
200 OK
{
   "count": <count>,
   "messages": [
     <message_id_1>,
     <message_id_2>,
     ...
   ],
   "status": "OK"
}
```

`message_id` is considered secret from the source side, meaning that a `message_id` allows to fetch or delete a message. `message_id` does not give any information about the content of the message, the sender, the receiver or any other metadata.

### /message/[message_id]

**Legend**:

| JSON Name | Value |
|---|---|
| `message_id` | Randomly generated unique, per message id. |
|`message_ciphertext` | *base64(E(k, m))* where *k* is a key agreement calculated key. The key agreement keys depend on the parties encrypting/decrypting the message. |
|`message_public_key` | *base64(ME<sub>PK</sub>)* |
|`message_challenge` | TODO: *base64()* |

#### POST
```
curl -X POST -H "Content_Type: application/json" http://127.0.0.1:5000/message --data
{
  "message_ciphertext": <message_ciphertext>,
  "message_public_key": <message_public_key>,
  "message_challenge": <message_challenge>
}
```
```
200 OK
{
  "status": "OK"
}
```

Note that `message_id` is not returned upon submission, so that the sending party cannot delete or fetch it unless they maliciously crafted the challenge for themselves, but at that point it would never be delivered to any other party.

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

### /file/[file_name]
Slicing and encrypting is up to the *Source* client. The server cannot enforce encryption, but it can enforce equal chunk size (TODO: not implemented).

**Legend**:

| JSON Name | Value |
|---|---|
|`file_id` | A unique, journalist-shared dictionary/hash-map key picked out of redis `file_token` set. Files are sliced, padded and encrypted to a fixed size so that all files looks equal and there are no metadata, however that is up to the uploading client. |
| `raw_encrypted_file_content` | Raw bytes composing the encrypted file object. |

#### POST
The `file_id` is public, meaning that just parties which know the corresponding `file_name` from the `file_token` redis set can either download the encrypted chunk or delete it. In production, it could be possible to set `commons.UPLOADS` to a FUSE filesystem without timestamps.

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
curl -X GET http://127.0.0.1:5000/file/<file_name>
```
```
200 OK
<raw_encrypted_file_content>
```
#### DELETE
A delete request deletes both the entry on the database and the encrypted chunk on the server storage.
```
curl -X DELETE http://127.0.0.1:5000/file/<file_name>
```
```
200 OK
{
  "status": "OK"
}
```

## Limitations
### Crypto
The cryptographic protocol needs to be audited. While we do not expect any major finding in the encryption protocol as it uses known primitives and known libraries in a well established manner, we cannot state the same for the challenge-response mechanism. 
  
The challenge-response mechanism provide a proof-of-decryption from a Source/Journalist to the Server. It leverages a particular property of Diffie-Hellman constructions: once a shared secret between two (or more) party has been established, it is possible for a party to remove their "share" if-and-only-if that party knows the asymmetric private key that was used to generate such shared secret. This allows the Server to "temporary" mix an ephemeral share every time a client ask to retrieve data, providing confusion to the state of the messages available at a given time.  

Any weakness of such challenge-response protocol would not hinder the trust chain or the confidentiality of messages since key segregation is also in place. A malicious party, it being either the Server or a Source, could fool the proof-of-decryption protocol and so retrieve the encrypted version of the messages but could not decrypt them to plaintext.  Still, this part is potentially the weak point of this proposal. We are confident that even if the challenge-response mechanism we design turns out to be insecure, there exists crypto primitives to achieve the same goal securely.

### Behavioral analysis
While there are no accounts, and all messages are equal, the server could detect if it is interacting with a source or a journalist by observing the API request pattern. While all the clients, both source and journalist, would go through the Tor network and look the same from an HTTP perspective, they might perform different actions, such as ephemeral keys upload. A further fingerprinting mechanism could be, for instance, measuring how much time any client takes to solve the challenge-responses. It is up to the clients to mitigate this, sending decoy traffic and introducing randomness between requests.

### Ephemeral key exhaustion
As a known problem in this kind of protocols, what happens when the ephemeral keys of a journalist are exhausted due to either malicious intent or infrequent upload by the journalist?

### Ephemeral key reuse (malicious server)
While it is not currently implemented, ephemeral keys should include a short (30/60 days) expiation date along with their PK signature. Journalists can routinely query the server for ephemeral keys and heuristically test if the server is being dishonest as well. They can also check during decryption as well and see if an already used key has worked: in that case the server is malicious as well.

### Decoy submissions
In the journalist client implementation, it could make sense to add both decoy API calls to obfuscate the behavioral pattern, as well as random submissions that then gets automatically ignored by the other journalists client when decrypted.

### Message retention
The server cannot keep too many messages with the current configuration, as more than 1k or 2k challenges at a time would be too much to compute reasonably for the clients. Messages needs either to be deleted upon read or to automatically expiry (after a few days maybe). In case of expiration, that expiration should have a degree of randomness, otherwise the expiration time would be the same of a submission date in the context of minimizing metadata.

### Denial of service
In having no accounts, it might be easy to flood the service, either of unwanted messages, or of bogus responses to challenges that would lead to significant waste of CPU resources. Depending on the individual *Newsroom* previous issues and threat model, classic rate limiting such as proof of work or captchas (even though we truly dislike them) could mitigate the issue.

### Minimize logging
To minimize logging, ans mix traffic better, it could be reasonable to make all endpoints the same and POST only and remove all GET parameters. An alternative solution could be to implement the full protocol over WebSockets.

### Revocation
Revocation is a spicy topic. For ephemeral keys, we expect expiration to be generally enough. For long-term keys, including eventual journalist de-enrollment or newsroom key rotation something along the standard has to be implemented, requiring eventually more infrastructure. For example, FPF could routinely publish a revocation list and host the Newsroom ones as well; however that must work even without FPF direct involvement. A good, already deployed, protocol for serving the revocation would be OCSP stapling served back directly by the SecureDrop server, so that clients (both sources and journalists) do not have to do external requests. Otherwise we could find a way to (ab)use the current internet revocation infrastructure and build on top of that.
