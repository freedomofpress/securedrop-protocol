# SecureDrop Protocol architecture

For an overview of the SecureDrop Protocol, see Berra et al. (2026), ["The
SecureDrop Protocol: End-to-End Encrypted Whistleblowing for All"][berra-2026],
including:

- Design goals
  - Security requirements
  - Adversary model
  - Use cases
- Related work
- Protocol design ([v0.3]): see the current [specification]
- Security analyses
- Implementation
  - Benchmarks
  - Deployment considerations
- References
- Ethical considerations

The rest of this document outlines design considerations and open questions that
are not reflected in this publication.

## Assumptions

- **This is a cryptographic protocol agnostic to the underlying transport.**
  In this proof-of-concept implementation, the server exposes a REST API; all
  parties communicate with the server via HTTP over Tor. A production
  implementation may use HTTP and/or WebSockets over Tor.

- **Message expiry/deletion will occur on a fuzzy interval.**
  The protocol will expire messages on the server at a fuzzy interval `d` days +/- `i` (for example, 37 +- 7 days would guarantee message availability for a minimum of 30 days). The goal of fuzzy-interval message expiry is to avoid writing precise metadata to disk about when a message was submitted, which would be implied by a fixed expiry time.
  Client-side (local) message deletion will be supported for journalists. Note this is not an anti-forensic measure, because some indicator will be retained in order to avoid re-downloading it.
  Detecting messages a client has already seen (i.e., preventing replay of the same protocol-level ciphertext) is an application-level responsibility on the journalist side (and not possible on the stateless source side).

- **Messaging an arbitrary subset of journalists will not be supported.**
  Journalists will be able to send group messages to all other journalists enrolled at their newsroom. Neither journalists nor sources will
  have individual messaging or arbitrary group messaging capabilities exposed to
  them via the UI.
  (The message delivery behaviour if a particular journalist's ephemeral key supply has been exhausted has yet to be finalized.)

- **The server OS and filesystem will minimize metadata.** OS implementation-level
  specifications are not part of the protocol, but it is assumed that file creation/deletion operations will not be logged to disk, and options will be explored for minimizing timestamps and other metadata at the filesystem level.

## Additional considerations for the threat model

Freedom of the Press Foundation (FPF) is the entity responsible for maintaining SecureDrop. FPF can offer additional services, such as dedicated support. While the project is open source, its components (SecureDrop releases, Onion Rulesets submitted upstream to Tor Browser) are signed with signing keys controlled by FPF. Despite this, SecureDrop is and will remain completely usable without any FPF involvement or knowledge.

- Is generally trusted
- Is based in the US
- Might get compromised technically
- Might get compromised legally
- Develops all the components and signs them
- Enrolls newsrooms

## Limitations and Discussion

### Behavioral analysis

Both source and journalist traffic would go through the Tor network, but they might perform different actions (such as uploading ephemeral keys). Mitigations, such as sending decoy traffic or introducing randomness between requests, must be implemented in the client.

### Ephemeral key exhaustion

A known problem with this type of protocol is the issue of ephemeral key exhaustion, either by an adversary or due to infrequent journalist activity.

### Ephemeral key reuse (malicious server)

Attempts by a malicious server to reuse ephemeral keys will need to be detected and mitigated.
Key expiration is not currently implemented, but ephemeral keys could include a short (30/60 day) expiration date along with their PK signature. Journalists can routinely query the server for ephemeral keys and heuristically test if the server is being dishonest as well. They can also check during decryption as well and see if an already used key has worked: in that case the server is malicious as well.

### Decoy traffic

One mitigation for behavioural analysis is the introduction of decoy traffic, which is readily compatible with this protocol. Since all messages and all submissions are structurally indistinguishable from a server perspective, as are all fetching operations, and there is no state or cookies involved between requests, any party on the internet could produce decoy traffic on any instance. Newsrooms, journalists or even FPF could produce all the required traffic just from a single machine.

### Denial of service

Without traditional accounts, it might be easy to flood the service with [too many messages][MAX_MESSAGES] or fetch requests that would be heavy on the server CPU. Depending on the individual _Newsroom_'s previous issues and threat model, classic rate-limiting techniques such as proof of work or captchas (even though we truly dislike them) could mitigate the issue.

### Message Observability

The public `requestMessages` endpoint must prevent a sender from observing whether a receiver has retrieved a particular message.

Implementors must ensure that:

- The server does not delete or mutate a message when a receiver successfully solves a challenge (no state change).
- The challenge list is regenerated with fresh randomness for each request.
- The server does not expose retrieval-dependent or message-dependent timing, logging, or status information.

The protocol uses a fixed nonce for challenge encryption because shared keys are constructed to be ephemeral. The key pair is derived from DH shares from the receiver fetch key and the ephemeral sender and server scalars. If a malicious sender reuses their DH scalar when constructing messages and the server uses a single scalar per-request, the derived key will be identical and the attacker may recover the plaintext message ID. Per-message scalars `r_k` MUST be used when using a fixed nonce for challenge encryption for message ID confidentiality.

This provides fetch-result **unobservability**: a sender cannot determine from the public API whether a receiver solved a challenge or retrieved a message.

### Challenge Unlinkability

Even with the measures in [Message Observability](#message-observability), a sender may still be able to recognize some of its messages in a challenge response.

If the server uses a single scalar `r` to blind each challenge in `requestMessages`, a malicious sender can submit algebraically related group elements for the challenges. For example, if two messages submitted use `X_1 = [2]G` and `X_2 = [4]G`, then the corresponding challenges satisfy `Q_1 = [r]X_1` and `Q_2 = [r]X_2 = [2]Q_1`.

After receiving the challenge list, the sender can identify which challenge entries correspond to its own messages.

Using independent per-message scalars `r_k` prevents this relationship except
with negligible probability. Per-message `r_k` therefore provides stronger
challenge-to-message unlinkability. This does not, by itself, reveal whether a message was fetched, as long as the server exposes no retrieval-dependent state change or timing side channel.

### DH Group-validation assumptions

Implementations must validate all untrusted group-element encodings and ensure
that every accepted public element belongs to the intended prime-order group used for the fetch challenges. This prevents small-subgroup and invalid-curve attacks and is required for the security of the challenge-response operations and the confidentiality of the fetch key.

### Minimize logging

To minimize logging, and mix traffic better, it could be reasonable to make all endpoints the same and POST only and remove all GET parameters. An alternative solution could be to implement the full protocol over WebSockets.

### Revocation

Revocation is a spicy topic. For ephemeral keys, we expect key expiration to be a sufficient measure. For long-term keys, it will be necessary to implement the infrastructure to support journalist de-enrollment and newsroom key rotation. For example, FPF could routinely publish a revocation list and host Newsroom revocation lists as well; however, a key design constraint is to ensure that the entire SecureDrop system can be set up autonomously, and can function even without FPF's direct involvement.

A good existing protocol for serving the revocation would be OCSP stapling served back directly by the SecureDrop server, so that clients (both sources and journalists) do not have to perform external requests. Otherwise we could find a way to (ab)use the current internet revocation infrastructure and build on top of that.

### More hardening

This protocol can be hardened further in specific parts, such as:

- rotating fetching keys regularly on the journalist side;
- adding a short (e.g., 30 day) expiration to ephemeral keys so that they are guaranteed to rotate even in case of malicious servers.

These details are left for internal team evaluation and production implementation constraints.

## Notes on other components

- **Keys**: When referring to keys, either symmetric or asymmetric, depending on the context, the key storage backend (i.e.: the media device) may eventually vary. Long term keys in particular can be stored on Hardware Security Modules or Smart Cards, and signing keys might also be a combination of multiple keys with special requirements (e.g., 3 out of 5 signers)
- **Server**: Besides the initial setup, all the connections to the server have to happen through the Tor Hidden Service Protocol. However, we can expect that a powerful attacker can find the server location and provider (through financial records, legal orders, de-anonymization attacks, logs of the setup phase).
- **Trust(ed) parties**: When referring to "trust" and "trusted" parties, the term "trust" is meant in a technical sense (as used in https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf), and not the social sense (as used in https://www.pewresearch.org/topic/news-habits-media/media-society/media-attitudes/trust-in-media/).

## Areas for further discussion

The following are areas of ongoing discussion/development or may be addressed by the application rather than the protocol level.

- **Key-fetch**: timing of key-fetch request (avoid timing information about partial/incomplete protocol runs). See also key exhaustion above.
- **Plaintext message structure**: specifically, application-level "metadata" (which could include non-cryptographic information such as key identifiers, or any other information encrypted along with the message plaintext and transmitted to the recipient) remains to be specified.
- **Message-fetch batching**: for now, one fetch request corresponds to one message_id, and multiple ids are not fetched at once.
- **One-time key choice/conflicts**: What to do with messages encrypted to recipient using same recipient key bundle remains to be discussed. See also https://github.com/freedomofpress/securedrop-protocol/issues/99.
- **Key lifetimes**: The lifetime of the journalist fetching key and journalist DH-AKEM reply key are still to be discussed. See also https://github.com/freedomofpress/securedrop-protocol/issues/99 for separate discussion of lifetime of journalist key bundles for receiving messages (currently one-time use).

[MAX_MESSAGES]: https://github.com/freedomofpress/securedrop-protocol/blob/d512528f42760f7ccb5205291ba11a377333cc0e/README.md?plain=1#L29
[berra-2026]: https://eprint.iacr.org/2026/1484
[specification]: ./protocol.md
[v0.3]: ./protocol.md#03
