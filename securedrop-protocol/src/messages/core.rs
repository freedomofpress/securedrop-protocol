use crate::primitives::{DHPublicKey, PPKPublicKey};
use crate::{Signature, VerifyingKey};
use alloc::vec::Vec;
use uuid::Uuid;

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

/// Message structure for Step 6: Source submits a message
///
/// This represents the message format before padding and encryption:
/// `msg || S_dh,pk || S_pke,pk || S_kem,pk || S_fetch,pk || J^i_sig,pk || NR`
#[derive(Clone)]
pub struct SourceMessage {
    /// The actual message content
    pub message: Vec<u8>,
    /// Source's DH public key
    pub source_dh_pk: DHPublicKey,
    /// Source's PKE public key
    pub source_pke_pk: PPKPublicKey,
    /// Source's KEM public key
    pub source_kem_pk: PPKPublicKey,
    /// Source's fetching public key
    pub source_fetch_pk: DHPublicKey,
    /// Journalist's signing public key
    pub journalist_sig_pk: VerifyingKey,
    /// Newsroom signing public key
    pub newsroom_sig_pk: VerifyingKey,
}

impl SourceMessage {
    /// Serialize the message into bytes for padding and encryption
    ///
    /// Note: Deviated from spec here to put variable length field last
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.source_dh_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.source_pke_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.source_kem_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.source_fetch_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.journalist_sig_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.newsroom_sig_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.message);
        bytes
    }
}

/// Message structure for Step 9: Journalist replies to a source
///
/// This represents the message format before padding and encryption:
/// `msg || S || J_sig,pk || J_fetch,pk || J_dh,pk || σ^NR || NR`
#[derive(Clone)]
pub struct JournalistReplyMessage {
    /// The actual message content
    pub message: Vec<u8>,
    /// Source identifier (UUID)
    pub source: Uuid,
    /// Journalist's signing public key
    pub journalist_sig_pk: VerifyingKey,
    /// Journalist's fetching public key
    pub journalist_fetch_pk: DHPublicKey,
    /// Journalist's DH public key
    pub journalist_dh_pk: DHPublicKey,
    /// Newsroom signature
    pub newsroom_signature: Signature,
    /// Newsroom signing public key
    pub newsroom_sig_pk: VerifyingKey,
}

impl JournalistReplyMessage {
    /// Serialize the message into bytes for padding and encryption
    ///
    /// TODO: I deviated from the spec here to put the message last
    /// because it's the only variable length field.
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.source.as_bytes()[0..16]);
        bytes.extend_from_slice(&self.journalist_sig_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.journalist_fetch_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.journalist_dh_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.newsroom_signature.0[0..64]);
        bytes.extend_from_slice(&self.newsroom_sig_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.message);

        bytes
    }
}

/// User submits a message to the server $(C, Z, X)$
///
/// This corresponds to step 6 for sources and step 9 for journalists in the spec.
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
pub struct MessageIdFetchRequest {}

/// Server returns encrypted message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageIdFetchResponse {
    /// Number of message entries returned
    pub count: usize,
    /// Array of (Q, cid) pairs where Q is the group DH share and cid is encrypted message ID
    pub messages: Vec<(Vec<u8>, Vec<u8>)>,
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
