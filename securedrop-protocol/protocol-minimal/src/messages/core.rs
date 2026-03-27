use crate::sign::{FpfOnNewsroom, NewsroomOnJournalist, Signature, VerifyingKey};
use crate::{FetchResponse, JournalistPublicView};
use alloc::vec::Vec;
use uuid::Uuid;

/// Request to fetch the newsroom's public keys from the server.
///
/// Used by both sources and journalists as the first request in step 5 of the spec.
pub struct NewsroomKeyRequest {}

/// Newsroom returns their keys and proof of onboarding.
///
/// This is the first response in step 5 of the spec.
pub struct NewsroomKeyResponse {
    pub newsroom_verifying_key: VerifyingKey,
    pub fpf_sig: Signature<FpfOnNewsroom>,
}

/// Request to fetch journalist keys from the server (`RequestKeys` in the spec).
///
/// This is step 5 in the spec. The server responds with long-term keys and a
/// one-time ephemeral key bundle for each available journalist.
pub struct KeyRequest {}

/// Server response to a `KeyRequest` (`pks, sigs` in the spec).
///
/// Contains one entry per journalist with their long-term keys, a one-time
/// ephemeral key bundle, and the associated signatures.
pub struct KeyResponse {
    pub journalist: JournalistPublicView,
    pub nr_signature: Signature<NewsroomOnJournalist>,
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
