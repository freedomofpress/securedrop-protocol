use crate::primitives::{DHPublicKey, PPKPublicKey};
use crate::{Signature, VerifyingKey};
use alloc::vec::Vec;

pub struct MessageBundle {}

/// Source fetches keys for the newsroom
///
/// This is the first request in step 5 of the spec.
pub struct SourceNewsroomKeyRequest {}

/// Newsroom returns their keys and proof of onboarding.
///
/// This is the first response in step 5 of the spec.
pub struct SourceNewsroomKeyResponse {
    newsroom_verifying_key: VerifyingKey,
    fpf_sig: Signature,
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
    journalist_sig_pk: VerifyingKey,
    /// Journalist's fetching public key
    journalist_fetch_pk: DHPublicKey,
    /// Journalist's long-term DH public key
    journalist_dh_pk: DHPublicKey,
    /// Newsroom's signature over journalist keys
    newsroom_sig: Signature,
    /// Random ephemeral DH public key for this journalist
    ephemeral_dh_pk: DHPublicKey,
    /// Random ephemeral KEM public key for this journalist
    ephemeral_kem_pk: PPKPublicKey,
    /// Random ephemeral PKE public key for this journalist
    ephemeral_pke_pk: PPKPublicKey,
    /// Journalist's signature over ephemeral keys
    journalist_ephemeral_sig: Signature,
}

/// Source submits a message to the server $(C, Z, X)$
///
/// This corresponds to step 6 in the spec.
pub struct SourceMessageSubmitRequest {
    /// Encrypted message ciphertext
    ciphertext: Vec<u8>,
    /// Diffie-Hellman share Z
    dh_share_z: Vec<u8>,
    /// Diffie-Hellman share X
    dh_share_x: Vec<u8>,
}

/// User (source or journalist) fetches message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageIdFetchRequest {}

/// Server returns encrypted message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageIdFetchResponse {
    /// Number of message entries returned
    count: usize,
    /// Array of (Q, cid) pairs where Q is the group DH share and cid is encrypted message ID
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
pub struct MessageFetchResponse {
    /// Encrypted message ciphertext
    ciphertext: Vec<u8>,
    /// Diffie-Hellman share X (only for source→journalist messages)
    dh_share_x: Option<Vec<u8>>,
}
