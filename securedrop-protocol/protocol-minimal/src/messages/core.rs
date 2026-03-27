use crate::sign::{FpfOnNewsroom, NewsroomOnJournalist, Signature, VerifyingKey};
use crate::{FetchResponse, JournalistPublicView};
use alloc::vec::Vec;
use uuid::Uuid;

/// Request to fetch the newsroom's public keys from the server.
///
/// Used by both sources and journalists as the first request in step 5 of the spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewsroomKeyRequest {}

/// Newsroom returns their keys and proof of onboarding.
///
/// This is the first response in step 5 of the spec.
#[derive(Debug)]
pub struct NewsroomKeyResponse {
    newsroom_verifying_key: VerifyingKey,
    fpf_sig: Signature<FpfOnNewsroom>,
}

impl NewsroomKeyResponse {
    /// Construct a new `NewsroomKeyResponse`.
    pub fn new(newsroom_verifying_key: VerifyingKey, fpf_sig: Signature<FpfOnNewsroom>) -> Self {
        Self {
            newsroom_verifying_key,
            fpf_sig,
        }
    }

    /// The newsroom's Ed25519 verifying key.
    pub fn newsroom_verifying_key(&self) -> &VerifyingKey {
        &self.newsroom_verifying_key
    }

    /// FPF's signature over the newsroom verifying key.
    pub fn fpf_sig(&self) -> &Signature<FpfOnNewsroom> {
        &self.fpf_sig
    }
}

/// Request to fetch journalist keys from the server (`RequestKeys` in the spec).
///
/// This is step 5 in the spec. The server responds with long-term keys and a
/// one-time ephemeral key bundle for each available journalist.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyRequest {}

/// Server response to a `KeyRequest` (`pks, sigs` in the spec).
///
/// Contains one entry per journalist with their long-term keys, a one-time
/// ephemeral key bundle, and the associated signatures.
#[derive(Debug)]
pub struct KeyResponse {
    journalist: JournalistPublicView,
    nr_signature: Signature<NewsroomOnJournalist>,
}

impl KeyResponse {
    /// Construct a new `KeyResponse`.
    pub fn new(
        journalist: JournalistPublicView,
        nr_signature: Signature<NewsroomOnJournalist>,
    ) -> Self {
        Self {
            journalist,
            nr_signature,
        }
    }

    /// The journalist's public keys.
    pub fn journalist(&self) -> &JournalistPublicView {
        &self.journalist
    }

    /// The newsroom's signature over the journalist's verifying key.
    pub fn nr_signature(&self) -> &Signature<NewsroomOnJournalist> {
        &self.nr_signature
    }
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
