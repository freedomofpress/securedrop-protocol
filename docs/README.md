# SecureDrop Protocol architecture
## Why is this unique?
What is implemented here is a small-scale, self-contained, anonymous message box, where anonymous parties (sources) can contact and receive replies from trusted parties (journalists). The whole protocol does not require server authentication, and every API call is independent and self-contained. Message submission and retrieval are completely symmetric for both sources and journalists, making the individual HTTP requests potentially indistinguishable. The server does not have information about message senders, receivers, the number of sources or login times, because there are no accounts, and therefore, no logins.

Nonetheless, the server must not reveal information about its internal state to external parties (such as generic internet users or sources), and must not allow those parties to enumerate or discern any information about messages stored on the server. To satisfy this constraint, a special message-fetching mechanism is implemented, where only the intended recipients are able to discover if they have pending messages.

## Assumptions

* **This is a cryptographic protocol agnostic to the underlying transport.**
  In this proof-of-concept implementation, the server exposes a REST API; all
  parties communicate with the server via HTTP over Tor.  A production
  implementation may use HTTP and/or WebSockets over Tor.
    * The protocol is amenable to mitigations against traffic analysis beyond
      the use of Tor, but they are out of the scope of this document.

* **Message expiry/deletion will occur on a fuzzy interval.** 
  The computation and bandwidth required for the message-fetching portion of this protocol limits the number of messages that can be stored on the server at once (a current estimate is that more than a few thousand would produce unreasonably slow computation times).
  The protocol will expire messages on the server at a fuzzy interval ``d`` days +/- ``i`` (for example, 37 +- 7 days would guarantee message availability for a minimum of 30 days). The goal of fuzzy-interval message expiry is to avoid writing precise metadata to disk about when a message was submitted, which would be implied by a fixed expiry time.
  Client-side (local) message deletion will be supported for journalists. Note this is not an anti-forensic measure, because some indicator will be retained in order to avoid re-downloading it.

* **Messaging an arbitrary subset of journalists will not be supported.**
  Messages from source to newsroom will be delivered to all* enrolled journalists for a given newsroom. Replies to sources from journalists will be delivered to all enrolled journalists plus the source. Journalists will be able to send group messages to all other journalists enrolled at their newsroom. Neither journalists nor sources will
  have individual messaging or arbitrary group messaging capabilities exposed to
  them via the UI.
  *(The message delivery behaviour if a particular journalist's ephemeral key supply has been exhausted has yet to be finalized).

* **The server OS and filesystem will minimize metadata.** OS implementation-level
  specifications are not part of the protocol, but it is assumed that file creation/deletion operations will not be logged to disk, and options will be explored for minimizing timestamps and other metadata at the filesystem level.

## Limitations and Discussion
### Behavioral analysis
While there are no user accounts, and all messages have the same structure from an HTTP perspective, the server could still detect if it is interacting with a source or a journalist by observing API request patterns. Both source and journalist traffic would go through the Tor network, but they might perform different actions (such as uploading ephemeral keys). A further fingerprinting mechanism could be, for instance, measuring how much time any client takes to fetch messages. Mitigations, such as sending decoy traffic or introducing randomness between requests, must be implemented in the client.

### Ephemeral key exhaustion
A known problem with this type of protocol is the issue of ephemeral key exhaustion, either by an adversary or due to infrequent journalist activity.

### Ephemeral key reuse (malicious server)
Attempts by a malicious server to reuse ephemeral keys will need to be detected and mitigated.
Key expiration is not currently implemented, but ephemeral keys could include a short (30/60 day) expiration date along with their PK signature. Journalists can routinely query the server for ephemeral keys and heuristically test if the server is being dishonest as well. They can also check during decryption as well and see if an already used key has worked: in that case the server is malicious as well.

### Decoy traffic
One mitigation for behavioural analysis is the introduction of decoy traffic, which is readily compatible with this protocol. Since all messages and all submissions are structurally indistinguishable from a server perspective, as are all fetching operations, and there is no state or cookies involved between requests, any party on the internet could produce decoy traffic on any instance. Newsrooms, journalists or even FPF could produce all the required traffic just from a single machine.

### Denial of service
Without traditional accounts, it might be easy to flood the service with unwanted messages or fetch requests that would be heavy on the server CPU. Depending on the individual *Newsroom*'s previous issues and threat model, classic rate-limiting techniques such as proof of work or captchas (even though we truly dislike them) could mitigate the issue.

### Covert communication
See https://github.com/freedomofpress/securedrop-protocol/issues/14.

### Minimize logging
To minimize logging, and mix traffic better, it could be reasonable to make all endpoints the same and POST only and remove all GET parameters. An alternative solution could be to implement the full protocol over WebSockets.

### Revocation
Revocation is a spicy topic. For ephemeral keys, we expect key expiration to be a sufficient measure. For long-term keys, it will be necessary to implement the infrastructure to support journalist de-enrollment and newsroom key rotation. For example, FPF could routinely publish a revocation list and host Newsroom revocation lists as well; however, a key design constraint is to ensure that the entire SecureDrop system can be set up autonomously, and can function even without FPF's direct involvement.

A good existing protocol for serving the revocation would be OCSP stapling served back directly by the SecureDrop server, so that clients (both sources and journalists) do not have to perform external requests. Otherwise we could find a way to (ab)use the current internet revocation infrastructure and build on top of that.

### More hardening
This protocol can be hardened further in specific parts, including: rotating fetching keys regularly on the journalist side; adding a short (e.g., 30 day) expiration to ephemeral keys so that they are guaranteed to rotate even in case of malicious servers; and allowing for "submit-only" sources that do not save the passphrase and are not reachable after first contact. These details are left for internal team evaluation and production implementation constraints.

## Notes on other components
  * **Keys**: When referring to keys, either symmetric or asymmetric, depending on the context, the key storage backend (i.e.: the media device) may eventually vary. Long term keys in particular can be stored on Hardware Security Modules or Smart Cards, and signing keys might also be a combination of multiple keys with special requirements (e.g., 3 out of 5 signers)
  * **Server**: For this project, a server might be a physical dedicated server housed in a trusted location, a physical server in an untrusted location, or a virtual server in a trusted or untrusted context. Besides the initial setup, all the connections to the server have to happen though the Tor Hidden Service Protocol. However, we can expect that a powerful attacker can find the server location and provider (through financial records, legal orders, de-anonymization attacks, logs of the setup phase).
  * **Trust(ed) parties**: When referring to "trust" and "trusted" parties, the term "trust" is meant in a technical sense (as used in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf), and not the social sense (as used in https://www.pewresearch.org/topic/news-habits-media/media-society/media-attitudes/trust-in-media/).