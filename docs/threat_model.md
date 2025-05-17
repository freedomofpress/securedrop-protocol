## Parties
  * **Source(s)**: A source is someone who wants to share information. A source is considered unknown prior to their first contact. A source may want to send a text message and/or add attachments, and may want to return at a later time to read replies. The source's safety, and their ability to preserve their anonymity, are vital; the higher the degree of plausible deniability a source has, the better. No on-device persistence shall be required for a source to interact with the system; they should be able to conduct all communications using only a single, theoretically-memorizable passphrase. The source uses Tor Browser to preserve their anonymity.
  * **Journalist(s)**: Journalists are those designated to receive, triage, and reply to submissions from sources. Journalists are not anonymous, and the newsroom they work for is a discoverable public entity. Journalists are expected to access SecureDrop via a dedicated client, which has persistent encrypted storage.
  * **Newsroom**: A newsroom is the entity with formal ownership of a SecureDrop instance. The newsroom is a known public entity, and is expected to publish information on how to reach their SecureDrop instance via verified channels (website, social media, print). In the traditional model, newsrooms are also responsible for their own server administration and journalist enrollment.
  * **FPF**: Freedom of the Press Foundation (FPF) is the entity responsible for maintaining SecureDrop. FPF can offer additional services, such as dedicated support. While the project is open source, its components (SecureDrop releases, Onion Rulesets submitted upstream to Tor Browser) are signed with signing keys controlled by FPF. Despite this, SecureDrop is and will remain completely usable without any FPF involvement or knowledge.

## Threat model summary
 * *FPF*
     * Is generally trusted
     * Is based in the US
     * Might get compromised technically
     * Might get compromised legally
     * Develops all the components and signs them
     * Enrolls newsrooms

 * *Newsroom*
     * Is generally trusted
     * Can be based anywhere
     * Might get compromised legally
     * Might get compromised technically
     * Manages a server instance
     * Enrolls journalists

 * *Server*
     * Is generally untrusted
     * Compromise requires effort
     * There may be backups or snapshots from any given point in time
     * RAM may be silently read
     * Managed and paid for by *Newsroom* or by a third party on their behalf

 * *Journalist*
     * Number can vary per *Newsroom*
     * Is generally trusted
     * Can travel
     * Physical and endpoint security depends on the workstation and client; out of scope here
     * Can be compromised occasionally
     * Reads submissions
     * Replies to submissions
     * Identity is generally known

 * *Source*:
     * Is completely untrusted
     * Anyone can be a source at any time
     * Requires ability to preserve anonymity if desired
     * Can read journalist replies to them
     * Can send messages to journalists
     * Can attach files

 * *Submission*:
     * Always from source to journalist (newsroom)
     * Generally specific to a single SecureDrop instance
     * Can be anything
     * Content is secret
     * Origin is secret
