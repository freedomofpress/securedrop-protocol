# Threat model

## Parties

- **Journalist(s)**: Journalists are those designated to receive, triage, and reply to submissions from sources. Journalists are not anonymous, and the newsroom they work for is a discoverable public entity. Journalists are expected to access SecureDrop via a dedicated client, which has persistent encrypted storage.
- **Newsroom**: A newsroom is the entity with formal ownership of a SecureDrop instance. The newsroom is a known public entity, and is expected to publish information on how to reach their SecureDrop instance via verified channels (website, social media, print). In the traditional model, newsrooms are also responsible for their own server administration and journalist enrollment.
- **FPF**: Freedom of the Press Foundation (FPF) is the entity responsible for maintaining SecureDrop. FPF can offer additional services, such as dedicated support. While the project is open source, its components (SecureDrop releases, Onion Rulesets submitted upstream to Tor Browser) are signed with signing keys controlled by FPF. Despite this, SecureDrop is and will remain completely usable without any FPF involvement or knowledge.

## Threat model summary

- _FPF_

  - Is generally trusted
  - Is based in the US
  - Might get compromised technically
  - Might get compromised legally
  - Develops all the components and signs them
  - Enrolls newsrooms

- _Newsroom_

  - Is generally trusted
  - Can be based anywhere
  - Might get compromised legally

- _Journalist_

  - Is generally trusted
  - Can travel
  - Physical and endpoint security depends on the workstation and client; out of scope here
  - Identity is generally known

- _Source_:

  - Can attach files

- _Submission_:
  - Can be anything
