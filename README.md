# securedrop-poc
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
for i in $(seq 0 9); do python3 journalist.py $i; done;
```

Send a message from the source to all journalists:
```
python3 source.py
```

Check the message from a journalist (0..9) and reply:
```
python3 journalist.py 7
```

Check the submission reply on the source side:
```
python3 source.py <source_passphrase>
```

## Demo instructions

## Parties
  * **Source**: A source is someone who wants to leak a document. A source is unknown prior its first contact. A source may want to send a text message and/or add attachments. The anonymity and safety of the source is vital. The source must use Tor Browser to preserve their anonymity and no persistance shall be required. The highest degree of deniability a source has, the better.
  * **Journalist(s)**: Journalists are those designated to receive, check and reply to submissions. Journalists are known, or at least the newsroom they work for is known and trusted. Journalists are expected to use the Securedrop Workstation with an ad-hoc client, which has dedicated encrypted storage.
  * **Newsroom**: A newsroom is the entity responsible or at least with formal ownership of a Securedrop instance. The newsroom is trusted, and is expected to publish their Securedrop instance somewhere, their tips page, their social media channel or wherever they want the necessary outreach. In the traditional model, newsroom are also technically in charge of their own server instances and of journalist enrollment.
  * **FPF**: FPF is the entity responsible for maintaining and developing Securedrop. FPF can offer additional services, such as dedicated support. FPF has already a leading role, in the context that, while the project is open source, releases and Onion Lists for Tor Browser are signed with FPF keys. However, the full stack must remain completely usable without any FPF involvement or knowledge.

## Notions
  * **Keys**: When referring to keys, either symmetric or asymmetric, depending on the context, the key storage backend (ie: the media device) may eventually vary. Especially long term keys can be stored on Hardware Security Modules or Smart Cards, and signing keys might also be a combination of multiple keys with specialy requirements (ie: 3 out of 5 signers)
  * **Server**: For this project a server might be a physical dedicated server housed in a trusted location, a physical server in an untrusted location, or a virtual server in a trusted or untrusted context. Besides the initial setup, all the connection to the server have to happen though the Tor Hidden Service Protocol. However, we can expect that a powerful attacker can find the server location and provider (through financial records, legal orders, deanonymization attacks, logs of the setup phase).

## Threat model

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
 * *c = E(k, m)*    → Encrypt message *m* to ciphertext *c* using symmetric key *k*
 * *m = D(k, c)*    → Decrypt ciphertext *c* to message *m* using symmetric key *k*
 * *h = H(m)*       → Hash message *m* to hash *h*
 * *p = KDF(m)*     → Derive a key *k* from message *m*
 * *SK, PK = G(s)*  → Generate a private key *SK* public key *PK* pair using seed *s*; if seed is empty generation is securely random
