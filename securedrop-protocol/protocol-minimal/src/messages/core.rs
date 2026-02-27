use crate::types::{FetchResponse, JournalistPublicView};
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
///
/// Updated for 0.3 spec with new key types:
/// - ephemeral_dh_pk: MLKEM-768 for message enc PSK (one-time)
/// - ephemeral_kem_pk: DH-AKEM for message enc (one-time)
/// - ephemeral_pke_pk: XWING for metadata enc (one-time)
/// TODO: this may be split into 2 responses, one that contains
/// static keys and one that contains one-time keys
pub struct SourceJournalistKeyResponse {
    pub journalist: JournalistPublicView,
    pub nr_signature: Signature,
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
    /// Array of FetchResponses, aka (enc_id, pmgdh) pairs, where encid/cid is encrypted message ID and pmgdh (Q) is the group DH share
    pub messages: Vec<FetchResponse>,
}

/// User fetches a specific message by ID
///
/// This corresponds to step 8 and 10 in the spec.
pub struct MessageFetchRequest {
    /// Message ID to fetch
    pub message_id: Uuid,
}
