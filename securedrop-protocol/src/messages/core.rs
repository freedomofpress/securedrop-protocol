use crate::client::StructuredMessage;
use crate::primitives::{
    PPKPublicKey, dh_akem::DhAkemPublicKey, mlkem::MLKEM768PublicKey, x25519::DHPublicKey,
    xwing::XWingPublicKey,
};
use crate::{SelfSignature, Signature, VerifyingKey};
use alloc::vec::Vec;
use uuid::Uuid;

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
///
/// Updated for 0.3 spec with new key types:
/// - ephemeral_dh_pk: MLKEM-768 for message enc PSK (one-time)
/// - ephemeral_kem_pk: DH-AKEM for message enc (one-time)
/// - ephemeral_pke_pk: XWING for metadata enc (one-time)
/// TODO: this may be split into 2 responses, one that contains
/// static keys and one that contains one-time keys
pub struct SourceJournalistKeyResponse {
    /// Journalist's signing public key
    pub journalist_sig_pk: VerifyingKey,
    /// Journalist's fetching public key
    pub journalist_fetch_pk: DHPublicKey,
    /// Journalist's long-term DH public key
    pub journalist_dhakem_sending_pk: DhAkemPublicKey,
    /// Newsroom's signature over journalist keys
    pub newsroom_sig: Signature,
    /// MLKEM-768 public key for message enc PSK (one-time)
    pub one_time_message_pq_pk: MLKEM768PublicKey,
    /// DH-AKEM public key for message enc (one-time)
    pub one_time_message_pk: DhAkemPublicKey,
    /// XWING public key for metadata enc (one-time)
    pub one_time_metadata_pk: XWingPublicKey,
    /// Journalist's signature over one-time keys
    pub journalist_ephemeral_sig: Signature,
    /// Journalist's signature over their long-term keys
    pub journalist_self_sig: SelfSignature,
}

/// Message structure for Step 6: Source submits a message
///
/// This represents the message format before padding and encryption:
/// `source_message_pq_pk || source_message_pk || source_metadata_pk || S_fetch,pk || J^i_sig,pk || NR || msg`
/// TODO: Decide on actual format
/// TODO: Just include a hash of the DH-AKEM public key, 0.3 description suggests that
#[derive(Clone)]
pub struct SourceMessage {
    /// The actual message content
    pub message: Vec<u8>,
    /// Source's MLKEM-768 public key for message enc PSK (one-time)
    pub source_message_pq_pk: MLKEM768PublicKey,
    /// Source's DH-AKEM public key for message enc (one-time)
    pub source_message_pk: DhAkemPublicKey,
    /// Source's XWING public key for metadata enc (one-time)
    pub source_metadata_pk: XWingPublicKey,
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
    /// Note: Deviated from 0.2 spec here to put variable length field last
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.source_message_pq_pk.as_bytes()[0..1184]);
        bytes.extend_from_slice(&self.source_message_pk.as_bytes()[0..32]);
        bytes.extend_from_slice(&self.source_metadata_pk.as_bytes()[0..1216]);
        bytes.extend_from_slice(&self.source_fetch_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.journalist_sig_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.newsroom_sig_pk.into_bytes()[0..32]);
        bytes.extend_from_slice(&self.message);
        bytes
    }
}

impl StructuredMessage for SourceMessage {
    fn into_bytes(self) -> Vec<u8> {
        self.into_bytes()
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

impl StructuredMessage for JournalistReplyMessage {
    fn into_bytes(self) -> Vec<u8> {
        self.into_bytes()
    }
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
    /// TODO: constant size array
    pub count: usize,
    /// Array of (Q, cid) pairs where Q is the group DH share and cid is encrypted message ID
    /// TODO: constant size array
    pub messages: Vec<(Vec<u8>, Vec<u8>)>,
}

/// User fetches a specific message by ID
///
/// This corresponds to step 8 and 10 in the spec.
pub struct MessageFetchRequest {
    /// Message ID to fetch
    pub message_id: u64,
}

/// Server returns the requested message
///
/// This corresponds to step 8 and 10 in the spec.
/// TODO: may remove alias
pub type MessageFetchResponse = MessageBundle;
