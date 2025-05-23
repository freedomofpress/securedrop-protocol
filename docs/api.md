# Server API

No endpoints require authentication or sessions. The only data store is Redis and is schema-less. Encrypted file chunks are stored to disk. No database bootstrap is required.

## /journalists

**Legend**:

| JSON Name                 | Value                                      |
| ------------------------- | ------------------------------------------ |
| `count`                   | Number of returned enrolled _Journalists_  |
| `journalist_key`          | _base64(J<sub>PK</sub>)_                   |
| `journalist_sig`          | _base64(sig<sup>NR</sup>(J<sub>PK</sub>))_ |
| `journalist_fetching_key` | _base64(JC<sub>PK</sub>)_                  |
| `journalist_fetching_sig` | _base64(sig<sup>J</sup>(JC<sub>PK</sub>))_ |

### POST

Adds _Newsroom_ signed _Journalist_ to the _Server_.

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

The server checks for proper signature using _NR<sub>PK</sub>_. If both signatures are valid, the request fields are added to the `journalists` Redis _set_.

### GET

Gets the journalists enrolled in _Newsroom_ and published in the _Server_.
The _Journalist_ UID is a hex encoded hash of the Journalist long-term signing key.

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
    },
    ...
  ],
  "status": "OK"
}
```

At this point _Source_ must have a verified _NR<sub>PK</sub>_ and must verify both _sig<sub>J</sub>_ and _sig<sub>JC</sub>_.

### DELETE (TODO)

_Not implemented yet. A Newsroom must be able to remove Journalists._

## /ephemeral_keys

**Legend**:

| JSON Name        | Value                                                                                                                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `count`          | Number of returned ephemeral keys. It should match the number of _Journalists_. If it does not, a specific _Journalist_ bucket might be out of keys. |
| `ephemeral_key`  | _base64(JE<sub>PK</sub>)_                                                                                                                            |
| `ephemeral_sig`  | _base64(sig<sup>J</sup>(JE<sub>PK</sub>))_                                                                                                           |
| `journalist_key` | _base64(J<sub>PK</sub>)_                                                                                                                             |

### POST

Adds _n_ _Journalist_ signed ephemeral key agreement keys to Server.
The keys are stored in a Redis _set_ specific per _Journalist_, which key is `journalist:<hex(public_key)>`. In the demo implementation, the number of ephemeral keys to generate and upload each time is `commons.ONETIMEKEYS`.

```
curl -X POST -H "Content-Type: application/json" "http://127.0.0.1:5000/ephemeral_keys" --data
{
  "journalist_key": <journalist_key>,
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

### GET

The server pops a random ephemeral*key from every enrolled journalist bucket and returns it. The `pop` operation effectively removes the returned keys from the corresponding \_Journalist* bucket.

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
      "journalist_key": <journalist_key>
    },
    ...
  ],
  "status": "OK"
}
```

At this point _Source_ must have verified all the J<sup>[0-i]</sup><sub>PK</sub>* and can thus verify all the corresponding *sig<sup>[0-n]</sup><sub>JE</sub>\*.

### DELETE (TODO)

_Not implemented yet. A Journalist shall be able to revoke keys from the server._

## /fetch

**Legend**:

| JSON Name  | Value                                                                                                                                                                                                                                                    |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `count`    | Number of returned potential messages. Must always be greater than the number of messages on the server. Equal to `commons.MAX_MESSAGES` so that it should always be the same for every request to prevent leaking the number of messages on the server. |
| `messages` | _(base64(pmgdh),base64(enc_mid))_                                                                                                                                                                                                                        |

#### GET

The server sends all the mixed group Diffie Hellman shares, plus the encrypted message id of the corresponding messsage. _gdh_ and _enc_ are paired in couples.

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

## /message/[message_id]

**Legend**:

| JSON Name            | Value                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `message_id`         | Randomly generated unique, per message id.                                                                                                       |
| `message_ciphertext` | _base64(Enc(k, m))_ where _k_ is a key agreement calculated key. The key agreement keys depend on the parties encrypting/decrypting the message. |
| `message_public_key` | _base64(ME<sub>PK</sub>)_                                                                                                                        |
| `message_gdh`        | _base64(ME<sub>SK</sub>,SC/JC<sub>PK</sub>)_                                                                                                     |

### POST

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

### GET

`message_public_key` is necessary for completing the key agreement protocol and obtaining the shared symmetric key to decrypt the message. `message_public_key`, is ephemeral, unique per message, and has no links to anything else.

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

### DELETE

```
curl -X DELETE http://127.0.0.1:5000/message/<message_id>
```

```
200 OK
{
  "status": "OK"
}
```

## /file/[file_id]

Slicing and encrypting is up to the _Source_ client. The server cannot enforce encryption, but it can enforce equal chunk size (TODO: not implemented).

**Legend**:

| JSON Name                    | Value                                                                                                                                                                                                |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `file_id`                    | Unique, randomly generated per upload id. Files are sliced, paded and encrypted to a fixed size so that all files looks equal and there are no metadata, however that is up to the uploading client. |
| `raw_encrypted_file_content` | Raw bytes composing the encrypted file object.                                                                                                                                                       |

### POST

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

### GET

The server will return either the raw encrypted content or a `404` status code.

```
curl -X GET http://127.0.0.1:5000/file/<message_id>
```

```
200 OK
<raw_encrypted_file_content>
```

### DELETE

A delete request deletes both the entry in the database and the encrypted chunk stored on the server.

```
curl -X DELETE http://127.0.0.1:5000/file/<file_id>
```

```
200 OK
{
  "status": "OK"
}
```
