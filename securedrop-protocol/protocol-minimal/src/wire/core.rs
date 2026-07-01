use crate::FetchResponse;
use crate::keys::{SignedKeyBundlePublic, SignedLongtermPubKeyBytes};
use crate::message::MessagePublicKey;
use crate::primitives::x25519::DHPublicKey;
use crate::sign::{
    FpfOnNewsroom, JournalistLongTermKey, NewsroomOnJournalist, Signature, VerifyingKey,
};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A journalist's long-term public key material, as carried in the
/// [`WelcomeBundle`].
///
/// Combined with a one-time [`SignedKeyBundlePublic`] (fetched separately
/// by an ephemeral key request) to reconstruct a `JournalistPublicView` for
/// encryption.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct JournalistLongTermView {
    pub vk: VerifyingKey,
    pub fetch_pk: DHPublicKey,
    pub reply_apke_pk: MessagePublicKey,
    pub signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    pub selfsig: Signature<JournalistLongTermKey>,
    pub nr_signature: Signature<NewsroomOnJournalist>,
}

/// The newsroom "welcome bundle" (step 5): this is everything a sender needs to
/// begin - the newsroom verifying key, FPF's signature over it, and the roster
/// of journalists' long-term keys/signatures.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct WelcomeBundle {
    pub newsroom_verifying_key: VerifyingKey,
    pub fpf_sig: Signature<FpfOnNewsroom>,
    pub journalists: Vec<JournalistLongTermView>,
}

/// One journalist's one-time (ephemeral) key bundle. `vk` identifies which
/// journalist - the server consumes the bundle when it serves it.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct JournalistEphemeralKeys {
    pub vk: VerifyingKey,
    pub ephemeral: SignedKeyBundlePublic,
}

/// User (source or journalist) fetches message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageChallengeFetchRequest {}

/// Server returns encrypted message IDs
///
/// This corresponds to step 7 in the spec.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
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
