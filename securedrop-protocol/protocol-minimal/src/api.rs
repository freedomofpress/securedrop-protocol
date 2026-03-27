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
//! 2. The newsroom's verifying key is signed by FPF.  (This is not yet verified by `handle_journalist_key_response()`.)
//! 3. Each journalist's signing key is signed by the newsroom.
//! 4. Each journalist's key bundles are self-signed.

use crate::{
    Enrollable, Envelope, FetchResponse, JournalistPublic, SignedKeyBundlePublic, UserPublic,
    UserSecret, VerifyingKey,
    encrypt_decrypt::{encrypt, solve_fetch_challenges},
    messages::{
        core::{
            MessageChallengeFetchRequest, MessageFetchRequest, NewsroomKeyRequest,
            NewsroomKeyResponse, SourceJournalistKeyRequest, SourceJournalistKeyResponse,
        },
        setup::{JournalistEphemeralKeyRequest, JournalistSetupRequest},
    },
};
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

/// Common client operations shared by sources and journalists.
///
/// Implementors must provide storage for the newsroom verifying key via
/// [`newsroom_verifying_key`](Api::newsroom_verifying_key) and
/// [`set_newsroom_verifying_key`](Api::set_newsroom_verifying_key).
/// All other methods have default implementations.
pub trait Api {
    /// Returns the stored newsroom verifying key, if one has been verified.
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey>;

    /// Stores a verified newsroom verifying key.
    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey);

    /// Creates a request to fetch the newsroom's public keys from the server.
    ///
    /// This is the first part of step 5 in the protocol spec.
    fn fetch_newsroom_keys(&self) -> NewsroomKeyRequest {
        NewsroomKeyRequest {}
    }

    /// Creates a request to fetch journalist public keys from the server.
    ///
    /// This is the second part of step 5 in the protocol spec. The server
    /// responds with long-term keys and a one-time ephemeral key bundle
    /// for each available journalist.
    fn fetch_journalist_keys(&self) -> SourceJournalistKeyRequest {
        SourceJournalistKeyRequest {}
    }

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
        let envelope = encrypt(rng, sender, plaintext, recipient);
        Ok(envelope)
    }

    /// Verifies and stores the newsroom's verifying key from a server response.
    ///
    /// Checks the FPF signature over the newsroom verifying key, and if valid,
    /// stores it for subsequent journalist key verification.
    ///
    /// # Errors
    ///
    /// Returns an error if the FPF signature is invalid.
    fn handle_newsroom_key_response(
        &mut self,
        response: &NewsroomKeyResponse,
        fpf_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        let newsroom_vk_bytes = response.newsroom_verifying_key.into_bytes();
        fpf_verifying_key
            .verify(&newsroom_vk_bytes, &response.fpf_sig)
            .map_err(|_| anyhow::anyhow!("invalid FPF signature on newsroom verifying key"))?;

        self.set_newsroom_verifying_key(response.newsroom_verifying_key);
        Ok(())
    }

    /// Verifies a journalist's key response against the newsroom's signature.
    ///
    /// Performs three signature checks:
    /// 1. The newsroom's signature over the journalist's verifying key.
    /// 2. The journalist's self-signature over their long-term key bundle.
    /// 3. The journalist's self-signature over their one-time keys.
    ///
    /// # Errors
    ///
    /// Returns an error if any signature check fails.
    fn handle_journalist_key_response(
        &self,
        response: &SourceJournalistKeyResponse,
        newsroom_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        // 1. Verify newsroom signature on journalist's verifying key.
        newsroom_verifying_key
            .verify(
                &response.journalist.verifying_key().into_bytes(),
                &response.nr_signature,
            )
            .map_err(|_| anyhow::anyhow!("invalid newsroom signature on journalist signing key"))?;

        // 2. Verify journalist's self-signature on long-term key bundle.
        let vk = response.journalist.verifying_key();
        vk.verify(
            response.journalist.signed_keybytes().as_bytes(),
            response.journalist.self_signature(),
        )
        .map_err(|_| anyhow::anyhow!("invalid journalist self-signature on long-term keys"))?;

        // 3. Verify journalist's self-signature on one-time ephemeral key bundle.
        vk.verify(
            &response.journalist.ephemeral_bundle().as_bytes(),
            response.journalist.ephemeral_signature(),
        )
        .map_err(|_| anyhow::anyhow!("invalid journalist self-signature on one-time keys"))?;

        Ok(())
    }
}

/// Restricts [`JournalistApi`] to types explicitly opted in by the crate.
///
/// This uses the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed)
/// to prevent downstream crates from implementing [`JournalistApi`].
pub(crate) mod restricted {
    pub trait RestrictedApi {}
}

/// Journalist-specific API operations.
///
/// Extends [`Api`] with enrollment and ephemeral key management. Only types
/// that implement the sealed [`RestrictedApi`](restricted::RestrictedApi) trait
/// can implement this, preventing misuse by downstream code.
pub trait JournalistApi: Api + restricted::RestrictedApi {
    /// Creates an enrollment request for initial journalist onboarding.
    ///
    /// Packages the journalist's self-signed long-term key bundle into a
    /// [`JournalistSetupRequest`] for submission to the newsroom (step 3.1).
    ///
    /// # Errors
    ///
    /// Returns an error if enrollment data cannot be constructed.
    fn create_setup_request(&self) -> Result<JournalistSetupRequest, Error>
    where
        Self: Enrollable,
    {
        Ok(JournalistSetupRequest {
            enrollment: self.enroll(),
        })
    }

    /// Creates a request to replenish ephemeral key bundles on the server.
    ///
    /// Collects all current signed key bundles and packages them into a
    /// [`JournalistEphemeralKeyRequest`] for upload to the server (step 3.2).
    fn create_ephemeral_key_request(&self) -> JournalistEphemeralKeyRequest
    where
        Self: Enrollable,
    {
        let bundles: Vec<SignedKeyBundlePublic> = self.signed_keybundles().collect();

        JournalistEphemeralKeyRequest {
            verifying_key: self.signing_key().clone(),
            bundles,
        }
    }
}
