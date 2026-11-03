

use crate::{
    Enrollable, Envelope, FetchResponse, JournalistPublicView, UserPublic, UserSecret,
    VerifyingKey,
    client::challenge::solve_fetch_challenges,
    client::message::encrypt,
    traits::RestrictedApi,
    wire::bundle::SignedKeyBundlePublic,
    wire::{
        core::{
            JournalistEphemeralKeys, JournalistLongTermView, MessageChallengeFetchRequest,
            MessageFetchRequest, WelcomeBundle,
        },
        setup::{JournalistEphemeralKeyRequest, JournalistSetupRequest},
    },
};
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

/// Clients hold a reference to the newsroom [`VerifyingKey`](VerifyingKey)
/// of the instance they are interacting with.
pub trait Client {
    /// Returns the stored newsroom verifying key, if one has been verified.
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey>;

    /// Stores a verified newsroom verifying key.
    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey);
}

/// Common API shared by sources and journalists. [`Api`](Api) users must provide
/// a Client implementation (local storage abstraction).
/// All users use the same API, but hax does not support default trait implementations
/// (cryspen/hax/issues/888) so the trait is defined separately.
pub trait Api: Client {
    /// Creates a request to fetch encrypted message IDs from the server.
    ///
    /// Corresponds to step 7 in the protocol spec. The server returns a
    /// fixed-size set of challenges (encrypted message IDs) that the client
    /// must solve using [`solve_fetch_challenges`](Api::solve_fetch_challenges).
    fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageChallengeFetchRequest;

    /// Solves the encrypted message-ID challenges returned by the server.
    ///
    /// Each [`FetchResponse`] contains an encrypted message ID and a
    /// per-request DH share. The client uses its fetch keypair to recover
    /// message IDs that were addressed to it, discarding the rest.
    ///
    /// Returns the set of [`Uuid`]s for messages belonging to this client.
    fn solve_fetch_challenges(&self, challenges: &[FetchResponse]) -> Result<Vec<Uuid>, Error>
    where
        Self: Sized + UserSecret;

    /// Creates a request to fetch a specific message by its ID.
    ///
    /// Corresponds to steps 8 and 10 in the protocol spec. Returns `None`
    /// if the request cannot be constructed (the default implementation
    /// always returns `Some`).
    fn fetch_message(&self, message_id: Uuid) -> Option<MessageFetchRequest>;

    /// Encrypts and submits a message from `sender` to `recipient`.
    ///
    /// Handles padding, plaintext construction (including sender reply keys),
    /// and hybrid encryption. This covers step 6 (source submissions) and
    /// step 9 (journalist replies) in the protocol spec.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    fn submit_message<R, S, P>(
        &self,
        rng: &mut R,
        message: &[u8],
        sender: &S,
        recipient: &P,
    ) -> Result<Envelope, Error>
    where
        R: RngCore + CryptoRng,
        S: UserSecret,
        P: UserPublic;

    /// Verifies a newsroom [`WelcomeBundle`] and stores the newsroom key (step 5).
    ///
    /// We check the FPF signature using the newsroom verifying key, then for every
    /// journalist in the roster we verify:
    /// * the newsroom's signature over the journalist's verifying key
    /// * the journalist's signature over their long term keys
    ///
    /// On success the newsroom key is stored, and the long term views can be
    /// cached and reused.
    ///
    /// # Errors
    ///
    /// Returns an error if the FPF signature or any journalist signature is invalid.
    fn handle_welcome(
        &mut self,
        welcome: &WelcomeBundle,
        fpf_verifying_key: &VerifyingKey,
    ) -> Result<(), Error>;

    /// Verifies one journalist's long-term view against a trusted newsroom verifying key,
    /// the newsroom's signature over the journalist's verifying key, and the
    /// journalist's signature over their long term keys.
    ///
    /// # Errors
    ///
    /// Returns an error if either signature is invalid.
    fn verify_long_term(
        &self,
        journalist: &JournalistLongTermView,
        newsroom_verifying_key: &VerifyingKey,
    ) -> Result<(), Error>;

    /// Verifies a list of journalists' one-time bundles against their already verified long-term view and assembles a list of `JournalistPublicView` for encryption. Discards any bundles that do not match a verification key in the roster.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature on the one-time bundle is invalid, or if the same journalist appears multiple times in the list.
    fn verify_ephemeral_keys(
        &self,
        roster: &[JournalistLongTermView],
        ephemeral: &[JournalistEphemeralKeys],
    ) -> Result<Vec<JournalistPublicView>, Error>;
}
