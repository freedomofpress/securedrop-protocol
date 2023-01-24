# securedrop-poc
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
| `UPLOADS` | `files/` | server | The folder where the Flask server will store uploaded files
| `JOURNALISTS` | `10` | server, source |  How many journalists do we create and enroll. In general, this is realistic, in current SecureDrop usage it is way less. For demo purposes everybody knows it, in a real scenario it would not be needed. |
| `ONETIMEKEYS` | `30` | journalist | How many ephemeral keys each journalist create, sign and uploads when required. |
| `CURVE` | `NIST384p` | server, source, journalist | The curve for all elliptic curve operations. It must be imported first from the python-ecdsa library. Ed25519 and Ed448, although supported by the lib, are not fully implemented. |
| `CHALLENGES` | `500` | server | How may challenges the server sends to each party when they try to fetch messages. This basically must be more than the messages in the database, otherwise we need to develop a mechanism to group challenges adding some bits of metadata. |
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
  * **Source**: A source is someone who wants to leak a document. A source is unknown prior its first contact. A source may want to send a text message and/or add attachments. The anonymity and safety of the source is vital. The source must use Tor Browser to preserve their anonymity and no persistence shall be required. The highest degree of deniability a source has, the better.
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
     * *DE<sub>PK</sub>*: Per-request, ephemeral decoy public key

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
     |NR<sub>SK</sub>, NR<sub>PK</sub> = G()* | Newsroom generates a random key-pair with similar security of the FPF one |
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

## Server endpoints
All endpoints do not require authentication or sessions. The only data store is Redis for more objects and is schema-less. Encrypted file chinks are stored to disk. No database bootstrap is required.
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
curl -X POST -H "Content-Type: application/json" "http://127.0.0.1:5000/journalists"
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
  ]
}
```

#### DELETE (TODO)
*Not implemented yet. A Newsroom shall be able to remove Journalists.*

### /ephemeral_keys
#### POST
#### GET
#### DELETE (TODO)

### /challenge/[challenge_id]
#### GET
#### POST

### /message/[message_id]
#### POST
#### GET
#### DELETE

### /file/[file_id]
#### POST
#### GET
#### DELETE
