use crate::primitives::{EphemeralDHPublicKey, FetchPublicKey, JournalistDHPublicKey, MessageEncPublicKey, MessagePQPSKEncapsKey, MetadataEncapsKey};
use crate::{Signature, VerifyingKey};
use alloc::vec::Vec;

/// (C, (Z, X)). Message payload to the server
pub struct MessageBundle {
    // C
    pub sealed_envelope: SealedEnvelope,
    // (Z, X)
    pub message_clue: MessageClue,
}

pub struct SealedEnvelope {
    /// HPKE AuthPSK Sealed ciphertext
    pub sealed_message: SealedMessage,

    // HPKE BaseMode Sealed X-WING encapsulated metadata (contains
    // sender pubkey needed to open SealedMessage.
    // See https://www.rfc-editor.org/rfc/rfc9180#section-9.9)
    pub sealed_metadata: SealedMessageMetadata,
    // X-WING shared secret encaps, 1120 bytes
    pub metadata_encaps: Vec<u8>,
}

/// Sealed metadata bytes
pub struct SealedMessageMetadata {}

/// Metadata for decrypting ciphertext
/// TODO: check int sizes
pub struct MessageMetadata {
    /// Message encryption key (DH-AKEM) is attached in metadata
    /// so that it can be used to open the authenticated sealed ct.
    /// Other keys are inside the ct
    pub sender_pubkey: MessageEncPublicKey,
    message_dhakem_secret_encaps: Vec<u8>,
    message_psk_secret_encaps: Vec<u8>,
}

/// Ciphertext bytes
pub struct SealedMessage {}


/// Plaintext message structure
pub struct Message {
    // TODO: if from journalist, these will be discarded because
    // a new one-time key bundle will be pulled; do we skip attaching these in journo messages?
    // Additional sender  pubkeys - attached only to allow replies
    pub sender_key_metadata: MetadataEncapsKey,
    pub sender_key_psk: MessagePQPSKEncapsKey,
    pub message_bytes: Vec<u8>,
    // TODO: Rest of message structure:
    // * newsroom identifier
    // * fetching key identifier?
    // * DH-AKEM key identifier (maybe not needed_?

}

/// (Z, X)
pub struct MessageClue {
    /// DH share
    pub clue_bytes: Vec<u8>,
    /// Ephemeral DH pubkey
    pub clue_pubkey: EphemeralDHPublicKey,
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
    /// Journalist's medium/long-term fetching public key
    pub journalist_fetch_pk: FetchPublicKey,

    /// Journalist's long-term DH public key
    /// TODO: haven't discussed if we will still have this key,
    /// if it will be a "key of last resport", or not
    pub journalist_dh_pk: JournalistDHPublicKey,
    /// Newsroom's signature over journalist keys
    pub newsroom_sig: Signature,
    /// Random one-time DH-AKEM public key for this journalist
    pub ephemeral_dh_pk: MessageEncPublicKey,
    /// Random one-time KEM encaps (public) key for this journalist
    pub ephemeral_kem_pk: MessagePQPSKEncapsKey,
    /// Random one-time Metadata encaps (public) key for this journalist
    pub ephemeral_pke_pk: MetadataEncapsKey,
    /// Journalist's signature over one-time keys
    pub journalist_ephemeral_sig: Signature,
}

/// User submits a message to the server $(C, Z, X)$
///
/// This corresponds to step 6 for sources and step 9 for journalists in the spec.
// TODO: could remove this, just kept it for consistency of naming with the other types
pub type MessageSubmitRequest = MessageBundle;

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
// TODO: may remove alias
pub type MessageFetchResponse = MessageBundle;
