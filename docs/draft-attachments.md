# SecureDrop Protocol attachments extension (draft)

| Version | Status |
| ------- | ------ |
| 0.1     | Draft  |

> [!NOTE]
> The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
> RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
> described in [RFC 2119].

## Table of contents

- [Overview](#overview)
- [Design goals and non goals](#design-goals-and-non-goals)
- [Building blocks](#building-blocks)
- [Formats](#formats)
- [Padding](#padding)
- [Server API](#server-api)
- [Validation](#validation)
- [Lifetime and deletion](#lifetime-and-deletion)
- [Security considerations](#security-considerations)
- [Open questions](#open-questions)
- [Changelog](#changelog)

## Overview

The core protocol carries short text messages. Attachments such as documents and images
are too large to include in a message ciphertext. This extension stores each attachment as a symmetrically encrypted blob on the
server, and delivers the information needed to retrieve and decrypt it in an attachment pointer. The attachment pointer is delivered inside an ordinary core protocol message. The pointer is small: a key, an identifier, and an integrity hash, so it fits within the
existing message payload.

At a high level:

1. The sender pads the attachment, and encrypts it under a fresh symmetric key, and uploads the ciphertext to a new unauthenticated `/file` endpoint.
2. The sender places a pointer to it (including the symmetric key) inside the message it sends via the core protocol.
3. The recipient decrypts the message as usual and extracts the pointer.
4. The receipient downloads the blob, verifies it, and decrypts it.

Because the pointer and therefore the symmetric key travels inside the
message ciphertext, the attachment inherits the message channel's
sender authentication and confidentiality, even though the blob itself is
stored unauthenticated and is fetched over a separate channel
(see [Security considerations](#security-considerations)).

## Design goals and non goals

Goals:

- Confidentiality of attachment contents against the server and network.
- Authenticity: a recipient accepts an attachment only if its key arrived over
  an authenticated message from a legitimate sender.
- Hide the exact attachment size from the server (via padding and size bucketing).

Non goals:

- Unobservability of attachment downloads. The `/file` GET is a distinct,
  linkable request - this extension does not provide the message fetching
  protocol's anonymity for blob retrieval (see [Security considerations](#security-considerations)).
- Streaming / chunked transfer of very large attachments (see
  [Open questions](#open-questions)).

## Building blocks

| Primitive | Choice | Notes |
| --------- | ------ | ----- |
| AEAD | ChaCha20-Poly1305 | 32 byte key, 16 byte tag |
| Hash | SHA-256 | Integrity hash over the stored blob. 32 byte output |
| Padding | `PAD()` (see [Padding](#padding)) | Applied to the plaintext before encryption |
| Key generation | 32 random bytes | One fresh key per attachment |

Because each attachment key is used exactly once, the AEAD nonce is fixed as all zero bytes and is not transmitted. Implementations MUST NOT reuse an attachment
key across blobs.

## Formats

### Attachment blob

The plaintext to be encrypted is framed so the recipient can recover the exact
original bytes after removing padding:

```
attachment_plaintext = original_len (u64, little endian)
                    || original_bytes
                    || zero_padding
```

where the total length of `attachment_plaintext` is `PAD(8 + len(original_bytes))`
and `zero_padding` is the zero bytes needed to reach that length.

The stored blob is the AEAD encryption of this plaintext under the per file key:

```
blob = ChaCha20-Poly1305.Enc(key, nonce = 0, ad = "", attachment_plaintext)
     = ciphertext || tag        // tag is 16 bytes
```

`original_len` lets the recipient strip
padding exactly, with no ambiguity even if the file ends in zero bytes.

### Attachment pointer

The pointer is serialized into the message to be end-to-end encrypted. It contains everything the recipient needs:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `version` | `u8` | Pointer/format version. `1` = v1 as specified here |
| `file_id` | opaque bytes | Server-assigned ID returned by `POST /file`. |
| `key` | `[u8; 32]` | ChaCha20-Poly1305 key for the blob. |
| `blob_hash` | `[u8; 32]` | SHA-256 over the stored `blob`. |
| `blob_len` | `u64` | Byte length of the stored `blob`. |

## Padding

Attachments MUST be padded before encryption. The padding target is
`PAD(n)` for input length `n`.

TODO: What padding makes sense? Buckets? Power of n too onerous?

## Server API

All endpoints are unauthenticated, consistent with the core public API.

| Method & path | Request | Response |
| ------------- | ------- | -------- |
| `POST /file` | `blob` bytes | `{ "file_id": ... }` | |
| `GET /file/{file_id}` | - | `blob` bytes, or `404` |

The POST endpoint submits the blob, assigns a fresh server-chosen `file_id`, and sets a fuzzy expiry. The server MUST reject blobs over the configured maximum size. The server SHOULD require proof-of-work for the `POST /file` endpoint.

## Validation

A recipient MUST treat a missing blob, a hash/length mismatch, or an AEAD
failure as a hard error and MUST NOT surface partial or unverified data.

## Lifetime and deletion

The server expires blobs after a fuzzy TTL, such that expiry timing does not precisely reveal
upload timing.

There is no user facing deletion endpoint, blobs are removed only on expiry.

## Security considerations

### Confidentiality and authenticity

Attachment contents are encrypted under a
key that exists only inside the end-to-end-encrypted message. The server and
network see only padded ciphertext. A recipient only learns a key from an authenticated SD-APKE
message.

### Padding leakage

Padding hides the exact size but not the size bucket.

### Abuse

The `/file` endpoint accepts larger payloads per request than the
message endpoint, so it is a more attractive target for resource exhaustion.
Implementations SHOULD apply a maximum blob size and a
stateless proof-of-work, plausibly with a heavier parameter than the message
endpoint.

## Open questions

- Padding scheme. TBD
- Maximum blob size. What cap balances usefulness against abuse and Tor
  transfer time?
- Chunking / streaming. Should large attachments be split into fixed size
  chunks (each independently encrypted)? Feasible
- Proof of work: One challenge per endpoint? Parameters?

## Changelog

### 0.1

Initial draft.
