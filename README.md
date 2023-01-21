# securedrop-poc
## Parties
  * _Source_: A source is someone who wants to leak a document. A source is unknown prior its first contact. A source may want to send a text message and/or add attachments. The anonymity and safety of the source is vital. The source must use Tor Browser to preserve their anonymity and no persistance shall be required. The highest degree of deniability a source has, the better.
  * _Journalist(s)_: Journalists are those designated to receive, check and reply to submissions. Journalists are known, or at least the newsroom they work for is known and trusted. Journalists are expected to use the Securedrop Workstation with an ad-hoc client, which has dedicated encrypted storage.
  * _Newsroom_: A newsroom is the entity responsible or at least with formal ownership of a Securedrop instance. The newsroom is trusted, and is expected to publish their Securedrop instance somewhere, their tips page, their social media channel or wherever they want the necessary outreach. In the traditional model, newsroom are also technically in charge of their own server instances and of journalist enrollment.
  * _FPF_: FPF is the entity responsible for maintaining and developing Securedrop. FPF can offer additional services, such as dedicated support. FPF has already a leading role, in the context that, while the project is open source, releases and Onion Lists for Tor Browser are signed with FPF keys. However, the full stack must remain completely usable without any FPF involvement or knowledge.

## Notions
  * _Keys_: When referring to keys, either symmetric or asymmetric, depending on the context, the key storage backend (ie: the media device) may eventually vary. Especially long term keys can be stored on Hardware Security Modules or Smart Cards, and signing keys might also be a combination of multiple keys with specialy requirements (ie: 3 out of 5 signers)
  * _Server_: For this project a server might be a physical dedicated server housed in a trusted location, a physical server in an untrusted location, or a virtual server in a trusted or untrusted context. Besides the initial setup, all the connection to the server have to happen though the Tor Hidden Service Protocol. However, we can expect that a powerful attacker can find the server location and provider (through financial records, legal orders, deanonymization attacks, logs of the setup phase).

## Threat model

## Keys summary
 * _FPF_:
  * *FPF<sub>SK</sub>*: Long term FPF signing private key
  * *FPF<sub>PK</sub>*: Long term FPF signing public key
 * _Newsroom_:
  * *NR<sub>SK</sub>*: Long term Newsroom signing private key
  * *NR<sub>PK</sub>*: Long term Newsroom signing public key
 * _Journalists_:
  * *J<sub>SK</sub>*: Long term Journalist signing private key
  * *J<sub>PK</sub>*: Long term Journalist signing public key
  * *JC<sub>SK</sub>*: Long term Journalist zero-knowledge private key
  * *JC<sub>PK</sub>*: Long term Journalist zero-knowledge public key
  * *JE<sub>SK</sub>*: Ephemeral (per-message) key agreement private key
  * *JE<sub>PK</sub>*: Ephemeral (per-message) key agreement public key
 * _Sources_:
  * *PW*: Secret passphrase
  * *S<sub>SK</sub>*: Long term Source key agreement private key
  * *S<sub>PK</sub>*: Long term Source key agreement public key
  * *SC<sub>SK</sub>*: Long term Source zero-knowledge private key
  * *SC<sub>PK</sub>*: Long term Source zero-knowledge public key
 * _Messages_:
  * *ME<sub>SK</sub>*: Ephemeral per-message key agreement private key
  * *ME<sub>PK</sub>*: Ephemeral per-message key agreement public key
