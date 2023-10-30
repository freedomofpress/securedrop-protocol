# Asymmetric construction: a visual primer

_Adapted from
<https://gist.github.com/cfm/f27e60fa2f2d2a4db899499fd8d29737#file-2-md>._

This diagram assigns ownership only to keys, not to values encrypted, decrypted,
or otherwise constructed from them. It color-codes values and constructions
according to what private keys they involve.

It's about a/symmetry of construction rather than flow of execution.

## Legend

- Labels from <https://github.com/freedomofpress/securedrop-poc/issues/16#issuecomment-1764436420>.

- Let `envelope1 = CONCAT(message1, sc_pub, se_pub)` for symmetry between the
  "message ID" and "message envelope" plaintexts.

- Let plaintext `X` → ciphertext `X'` → plaintext `X''` or recovered `X!`.

- **FIXME:** Let _seal_ replace "challenges" and "attestations" (which these
  aren't) and shared secrets (which these are; but how are they being _used_?).

---

```mermaid
graph TD

classDef Journo stroke:#F00
classDef Server stroke:#0F0
classDef Source stroke:#00F
classDef All stroke-dasharray:5,5

subgraph "Legend by private-key involvement"
subgraph parties
_Journo["Journalist"]:::Journo
_Server["Server"]:::Server
_Source["Source"]:::Source
end

subgraph "two-party agreement"
_JoSe["Journalist+Server"]
style _JoSe stroke:#FF0
_SoSe["Source+Server"]
style _SoSe stroke:#0FF
_SoJo["Journalist+Source"]
style _SoJo stroke:#F0F
end
subgraph "three-party agreement"
_All["Journalist+Server+Source"]:::All
end
end

subgraph Journo
jc_priv:::Journo --G--> jc_pub
je_priv:::Journo --G--> je_pub
end
class Journo Journo

subgraph Server
re_priv1>re_priv1]:::Server
message_id>message_id]
end
class Server Server;

subgraph Source
sc_priv:::Source --G--> sc_pub
se_priv:::Source --G--> se_pub

message1>message1]
me_priv1>me_priv1]:::Source
me_priv1 --G--> me_pub1
end
class Source Source

jc_pub --> source_seal_for_journo1
me_priv1 --> source_seal_for_journo1:::Source
linkStyle 6 stroke:#00F

je_pub --> envelope_key
me_priv1 --> envelope_key:::Source
linkStyle 8 stroke:#00F

message1 --> envelope1
sc_pub --> envelope1
se_pub --> envelope1
envelope1 --> envelope1'
envelope_key --> envelope1':::Source
linkStyle 13 stroke:#00F

me_pub1 --> server_seal_for_message1
re_priv1 --> server_seal_for_message1:::Server
linkStyle 15 stroke:#0F0

source_seal_for_journo1 --> server_joins_source_seal_for_journo1
linkStyle 16 stroke:#00F
re_priv1 --> server_joins_source_seal_for_journo1
linkStyle 17 stroke:#0F0
style server_joins_source_seal_for_journo1 stroke:#0FF

server_joins_source_seal_for_journo1 --> message_id'
linkStyle 18 stroke:#0FF
message_id --> message_id'
style message_id' stroke:#0FF

server_seal_for_message1 --> journo_joins_server_seal_for_message1
linkStyle 20 stroke:#0F0
jc_priv --> journo_joins_server_seal_for_message1
linkStyle 21 stroke:#F00
style journo_joins_server_seal_for_message1 stroke:#FF0

journo_joins_server_seal_for_message1 --> message_id''
linkStyle 22 stroke:#FF0
message_id' --> message_id'':::All
linkStyle 23 stroke:#0FF

me_pub1 --> envelope_key!
je_priv --> envelope_key!:::Journo
linkStyle 25 stroke:#F00

envelope_key! --> envelope1''
linkStyle 26 stroke:#F00
envelope1' --> envelope1''
linkStyle 27 stroke:#00F
style envelope1'' stroke:#F0F

envelope1'' --> message1''
envelope1'' --> sc_pub''
envelope1'' --> se_pub''
```
