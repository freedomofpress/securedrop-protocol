use crate::primitives::{DHPublicKey, PPKPublicKey};
use crate::{Signature, VerifyingKey};
use alloc::vec::Vec;

pub struct MessageBundle {
    /// C
    pub sealed_envelope: SealedEnvelope,
    /// (Z, X)
    pub message_clue: MessageClue,
}

pub struct SealedEnvelope {
    /// HPKE AuthPSK Sealed ciphertext
    pub sealed_message: SealedMessage,

    /// HPKE BaseMode Sealed X-WING encapsulated metadata (contains
    /// sender pubkey needed to open SealedMessage.
    /// See https://www.rfc-editor.org/rfc/rfc9180#section-9.9)
    pub sealed_metadata: SealedMessageMetadata,
    /// X-WING shared secret encaps, 1120 bytes
    pub metadata_encaps: Vec<u16>,
}

/// Sealed metadata bytes
pub struct SealedMessageMetadata {}

/// Metadata for decrypting ciphertext
/// TODO: check int sizes
pub struct MessageMetadata {
    pub sender_key: DHPublicKey,
    message_dhakem_secret_encaps: Vec<u8>,
    message_psk_secret_encaps: Vec<u8>,
}

/// Ciphertext bytes
pub struct SealedMessage {}

/// TODO: Plaintext message structure (i.e what keys or hashes of keys are included?)
/// At minimum:
/// Sender XWING key (for replies metadata)
/// Sender MLKEM key (for replies)
/// Identifiers: newsroom identifier
/// Fetching key identifier?
/// DH-AKEM key identifier (maybe not needed bc of how auth mode in hpke works)?
/// Plaintext
//pub struct Message {}

/// (Z, X)
pub struct MessageClue {
    /// DH share
    pub clue_bytes: Vec<u8>,
    /// Ephemeral DH pubkey
    pub clue_pubkey: DHPublicKey,
}

/// Source fetches keys for the newsroom
///
/// This is the first request in step 5 of the spec.
pub struct SourceNewsroomKeyRequest {}

/// Newsroom returns their keys and proof of onboarding.
///
/// This is the first response in step 5 of the spec.
pub struct SourceNewsroomKeyResponse {
    pub newsroom_verifying_key: VerifyingKey,
    pub fpf_sig: Signature,
}

/// Source fetches journalist keys for the newsroom
///
/// This is part of step 5 in the spec.
///
/// Note: This isn't currently written down in the spec, but
/// should occur right before the server provides a long-term
/// key and an ephmeral key bundle for the journalist.
pub struct SourceJournalistKeyRequest {}

/// Server returns journalist long-term keys and ephemeral keys
///
/// This is the second part of step 5 in the spec.
pub struct SourceJournalistKeyResponse {
    /// Journalist's signing public key
    pub journalist_sig_pk: VerifyingKey,
    /// Journalist's fetching public key
    pub journalist_fetch_pk: DHPublicKey,
    /// Journalist's long-term DH public key
    pub journalist_dh_pk: DHPublicKey,
    /// Newsroom's signature over journalist keys
    pub newsroom_sig: Signature,
    /// Random ephemeral DH public key for this journalist
    pub ephemeral_dh_pk: DHPublicKey,
    /// Random ephemeral KEM public key for this journalist
    pub ephemeral_kem_pk: PPKPublicKey,
    /// Random ephemeral PKE public key for this journalist
    pub ephemeral_pke_pk: PPKPublicKey,
    /// Journalist's signature over ephemeral keys
    pub journalist_ephemeral_sig: Signature,
}

/// User submits a message to the server $(C, Z, X)$
///
/// This corresponds to step 6 for sources and step 9 for journalists in the spec.
/// TODO: could remove this, just kept it for consistency of naming with the other types
pub type MessageSubmitRequest = MessageBundle;

#[derive(Clone)]
pub struct Message {
    /// Encrypted message ciphertext
    pub ciphertext: Vec<u8>,
    /// Diffie-Hellman share Z
    pub dh_share_z: Vec<u8>,
    /// Diffie-Hellman share X
    pub dh_share_x: Vec<u8>,
}

/// User (source or journalist) fetches message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageChallengeFetchRequest {}

/// Server returns encrypted message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageChallengeFetchResponse {
    /// Number of message entries returned
    /// TODO: constant size response
    count: usize,
    /// Array of (Q, cid) pairs where Q is the group DH share and cid is encrypted message ID
    /// TODO: constant size array
    messages: Vec<(Vec<u8>, Vec<u8>)>,
}

/// User fetches a specific message by ID
///
/// This corresponds to step 8 and 10 in the spec.
pub struct MessageFetchRequest {
    /// Message ID to fetch
    message_id: u64,
}

/// Server returns the requested message
///
/// This corresponds to step 8 and 10 in the spec.
/// TODO: may remove alias
pub type MessageFetchResponse = MessageBundle;
