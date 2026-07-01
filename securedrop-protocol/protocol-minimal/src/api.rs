//! Client API traits for the SecureDrop protocol.
//!
//! This module defines the shared API surface for both source and journalist
//! clients. The [`Api`] trait provides common operations such as key fetching,
//! signature verification, and message submission. The [`JournalistApi`] trait
//! extends [`Api`] with journalist-specific operations like enrollment and
//! ephemeral key management.
//!
//! # Trust model
//!
//! Key verification follows a chain of trust:
//! 1. The FPF signing key is a trust anchor (pre-distributed out of band).
//! 2. The newsroom's verifying key is signed by FPF.
//! 3. Each journalist's signing key is signed by the newsroom.
//! 4. Each journalist's long-term and one-time key bundles are self-signed.

use crate::{
    Enrollable, Envelope, FetchResponse, JournalistPublicView, UserPublic, UserSecret,
    VerifyingKey,
    encrypt_decrypt::{encrypt, solve_fetch_challenges},
    keys::SignedKeyBundlePublic,
    traits::RestrictedApi,
    wire::{
        core::{
            JournalistLongTermView, MessageChallengeFetchRequest, MessageFetchRequest,
            WelcomeBundle,
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

    /// Verifies a journalist's one-time bundle against their already verified
    /// long-term view and assembles a `JournalistPublicView` for encryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature on the one-time bundle is invalid.
    fn verify_ephemeral(
        &self,
        long_term: &JournalistLongTermView,
        ephemeral: &SignedKeyBundlePublic,
    ) -> Result<JournalistPublicView, Error>;
}

impl<T> Api for T
where
    T: Client,
{
    /// Creates a request to fetch encrypted message IDs from the server.
    ///
    /// Corresponds to step 7 in the protocol spec. The server returns a
    /// fixed-size set of challenges (encrypted message IDs) that the client
    /// must solve using [`solve_fetch_challenges`](Api::solve_fetch_challenges).
    fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageChallengeFetchRequest {
        MessageChallengeFetchRequest {}
    }

    /// Solves the encrypted message-ID challenges returned by the server.
    ///
    /// Each [`FetchResponse`] contains an encrypted message ID and a
    /// per-request DH share. The client uses its fetch keypair to recover
    /// message IDs that were addressed to it, discarding the rest.
    ///
    /// Returns the set of [`Uuid`]s for messages belonging to this client.
    fn solve_fetch_challenges(&self, challenges: &[FetchResponse]) -> Result<Vec<Uuid>, Error>
    where
        Self: Sized + UserSecret,
    {
        Ok(solve_fetch_challenges(self, challenges))
    }

    /// Creates a request to fetch a specific message by its ID.
    ///
    /// Corresponds to steps 8 and 10 in the protocol spec. Returns `None`
    /// if the request cannot be constructed (the default implementation
    /// always returns `Some`).
    fn fetch_message(&self, message_id: Uuid) -> Option<MessageFetchRequest> {
        Some(MessageFetchRequest { message_id })
    }

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
        P: UserPublic,
    {
        // TODO: review padding
        let padded_message = crate::primitives::pad::pad_message(message);
        let plaintext = sender.build_message(padded_message);
        let envelope = encrypt(rng, sender, &plaintext, recipient);
        Ok(envelope)
    }

    fn handle_welcome(
        &mut self,
        welcome: &WelcomeBundle,
        fpf_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        let newsroom_vk = welcome.newsroom_verifying_key;
        fpf_verifying_key
            .verify(&newsroom_vk.into_bytes(), &welcome.fpf_sig)
            .map_err(|_| anyhow::anyhow!("invalid FPF signature on newsroom verifying key"))?;

        for journalist in welcome.journalists.iter() {
            self.verify_long_term(journalist, &newsroom_vk)?;
        }

        self.set_newsroom_verifying_key(newsroom_vk);
        Ok(())
    }

    fn verify_long_term(
        &self,
        journalist: &JournalistLongTermView,
        newsroom_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        newsroom_verifying_key
            .verify(&journalist.vk.into_bytes(), &journalist.nr_signature)
            .map_err(|_| anyhow::anyhow!("invalid newsroom signature on journalist signing key"))?;
        journalist
            .vk
            .verify(
                journalist.signed_longterm_key_bytes.as_bytes(),
                &journalist.selfsig,
            )
            .map_err(|_| anyhow::anyhow!("invalid journalist self-signature on long-term keys"))?;
        Ok(())
    }

    fn verify_ephemeral(
        &self,
        long_term: &JournalistLongTermView,
        ephemeral: &SignedKeyBundlePublic,
    ) -> Result<JournalistPublicView, Error> {
        long_term
            .vk
            .verify(&ephemeral.0.as_bytes(), &ephemeral.1)
            .map_err(|_| anyhow::anyhow!("invalid journalist self-signature on one-time keys"))?;

        Ok(JournalistPublicView::new(
            long_term.vk,
            long_term.fetch_pk.clone(),
            long_term.reply_apke_pk.clone(),
            long_term.selfsig,
            long_term.signed_longterm_key_bytes.clone(),
            ephemeral.clone(),
        ))
    }
}

/// Provide generic implementation, restricted to implementors RestrictedApi trait and
/// the Enrollable trait. Implementors of both those will automatically be able to use
/// this generic JournalistApi implementation, but downstream crates will be unable to
/// implement RestrictedApi. Originally this was defined at the trait level
/// (`pub trait JournalistApi: Api + restricted::RestrictedApi`), but hax was unable
/// to extract the trait.
impl<T> JournalistApi for T
where
    T: Api + Enrollable + RestrictedApi,
{
    fn create_setup_request(&self) -> Result<JournalistSetupRequest, Error> {
        Ok(JournalistSetupRequest {
            enrollment: self.enroll(),
        })
    }

    fn create_ephemeral_key_request(&self) -> JournalistEphemeralKeyRequest {
        JournalistEphemeralKeyRequest {
            verifying_key: self.signing_key().clone(),
            bundles: self.signed_keybundles(),
        }
    }
}

/// Journalist-specific API operations.
///
/// Extends [`Api`] with enrollment and ephemeral key management.
pub trait JournalistApi {
    /// Creates an enrollment request for initial journalist onboarding.
    ///
    /// Packages the journalist's self-signed long-term key bundle into a
    /// [`JournalistSetupRequest`] for submission to the newsroom (step 3.1).
    ///
    /// # Errors
    ///
    /// Returns an error if enrollment data cannot be constructed.
    fn create_setup_request(&self) -> Result<JournalistSetupRequest, Error>;

    /// Creates a request to replenish ephemeral key bundles on the server.
    ///
    /// Collects all current signed key bundles and packages them into a
    /// [`JournalistEphemeralKeyRequest`] for upload to the server (step 3.2).
    fn create_ephemeral_key_request(&self) -> JournalistEphemeralKeyRequest;
}
