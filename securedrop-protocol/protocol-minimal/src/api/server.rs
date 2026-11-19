//! Component abstraction boundaries for SecureDrop protocol.
//!
//! This module defines the shared API surface for both source and journalist
//! clients, specified by [`ApplicationContract`](ApplicationContract).
//! Requirements are specified as traits and treated as a contract between the
//! various components, so an API change will be a breaking change and should
//! be handled accordingly.
//!
//! A client application provides:
//!  * A secure high-entropy randomness source, [`HasRng`](HasRng)
//!  * An implementation of the [`ClientProtocol`](ClientProtocol).
//!    The DefaultProtocol implementation provided below is suggested.
//!  * An implementation of [`Api`](Api), the required network calls.
//!    (Journalist application may supply the [`JournalistApi`](JournalistApi),
//!    which extends [`Api`] with journalist-specific API calls for enrollment and
//!    ephemeral key management).
//!  * A reference to the per-instance [`VerifyingKey`](VerifyingKey) (NewsroomKey)
//!  * Optionally, an implementation of the [`ApplicationCallback`](ApplicationCallback) methods, meant for
//!    interacting with the presentation layer/GUI.
//!
//! # Trust model
//!
//! Key verification follows a chain of trust:
//! 1. The FPF signing key is a trust anchor (pre-distributed out of band).
//! 2. The newsroom's verifying key is signed by FPF.
//! 3. Each journalist's signing key is signed by the newsroom.
//! 4. Each journalist's long-term and short-term key bundles are self-signed.

use crate::{
    Enrollable, Envelope, FetchResponse, Journalist, JournalistPublicView, UserPublic, UserSecret,
    VerifyingKey,
    api::common::HasRng,
    client::{challenge::solve_fetch_challenges, message::encrypt},
    sealed,
    traits::RestrictedApi,
    wire::{
        bundle::SignedKeyBundlePublic,
        core::{
            JournalistEphemeralKeys, JournalistLongTermView, MessageChallengeFetchRequest,
            MessageChallengeFetchResponse, MessageFetchRequest, WelcomeBundle,
            WelcomeBundleRequest,
        },
        setup::{
            JournalistEphemeralKeyRequest, JournalistEphemeralKeyResponse, JournalistSetupRequest,
            JournalistSetupResponse,
        },
    },
};

/// Server requirements
pub trait ServerContract: HasRng {
    // May not be exposed outside the Welcome bundle. May or may not be signed by FPF key.
    // This is "Newsroom Verifying Key".
    fn verifying_key(&self) -> Result<VerifyingKey, ServerApiError>;

    /// (GET) "Welcome Bundle" (Roster information)
    /// Handles client [`Api::request_keys`](Api::request_keys)
    fn welcome(&self, req: WelcomeBundleRequest) -> Result<WelcomeBundle, ServerApiError>;

    /// (GET) Challenges
    /// Handles client [`Api::fetch_challenges`](Api::fetch_challenges)
    fn challenges(
        &mut self,
        req: MessageChallengeFetchRequest,
    ) -> Result<MessageChallengeFetchResponse, ServerApiError>;

    /// (GET) Single encrypted message by UUID, if corresponding entry exists in server store
    /// Handles client [`Api::fetch_message`](Api::fetch_message)
    fn message_get(&self, req: MessageFetchRequest) -> Result<Option<Envelope>, ServerApiError>;

    /// (PUT) Encrypted message (envelope)
    /// Handles client [`Api::submit_message`](Api::submit_message)
    fn message_submit(&mut self, ct: Envelope) -> Result<(), ServerApiError>;

    /// (PUT) Journalist into roster (add new)
    fn journalist_enroll(
        &mut self,
        req: JournalistSetupRequest,
    ) -> Result<JournalistSetupResponse, ServerApiError>;

    /// (PUT) Journalist short-lived keys (replenish)
    fn journalist_short_lived_keys(
        &mut self,
        req: JournalistEphemeralKeyRequest,
    ) -> Result<JournalistEphemeralKeyResponse, ServerApiError>;
}

// Server can/should return its own error type, this is a placeholder
pub type ServerApiError = anyhow::Error;
