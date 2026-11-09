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

/// Any implementing application must have a suitable randomness source
pub trait HasRng {
    type Rng: CryptoRng + RngCore;
    // Todo: we may decide on another implementation pattern that doesn't expose
    // the rng to downstream implementors, for example an Application<R: Rng> struct
    // that takes the rng as a parameter.
    // This approach allows downstream implementors to define their own application struct,
    // but exposes the fn rng().
    #[doc(hidden)]
    fn rng(&self) -> &mut Self::Rng;
}

/// The following defines the requirements for an application that runs SecureDrop Protocol.
///
/// An implementing application should implement this trait and the methods it requires,
/// and all requirements should be expressed via trait functionality, such that implementing
/// this contract is sufficient to operate SecureDrop Protocol from the protocol's perspecive.
///
/// The [`ApplicationContract`](ApplicationContract) is storage-agnostic.
/// Implementing applications may provide the storage backend of their choice, including an
/// in-memory-only backend. The associated trait types operate statelessly.
///
pub trait ApplicationContract: HasRng {
    /// A client application fulfills API contract.
    /// All networking calls the application makes should be part of this contract.
    type NetworkApi: Api;

    /// A client application interacts with the underlying protocol.
    /// All such interactions use methods specified by the ClientProtocol trait.
    /// Other than types, no other protocol internals should be exposed.
    type Protocol: ClientProtocol;

    // If a Storage abstraction is useful, its core operations can be defined as a trait.
    // type Storage: Storage;

    // A callback responds to events, either user input or results from predefined operations,
    // and provides a way to update the GUI.
    // These are customizable by each client.
    // GUI/presentation-layer events should be handled through callbacks, not by modifying
    // API or Protocol method impls or creating side-effects that occur during other methods.
    // If a new GUI event is required, prefer explicit events with parameterizable methods
    // over stateful/self-referential events with side-effects.
    // (ie &self.set_flag(something) is a smell!)
    type Callback: ApplicationCallback;

    ////////////////////////////
    // Begin core functionality
    ////////////////////////////

    // We may change how the VerifyingKey is provided, but for now this is OK
    /// Returns the stored newsroom verifying key, if one has been verified.
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey>;

    /// Stores a verified newsroom verifying key.
    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey);

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
    ) -> Result<(), Error> {
        let newsroom_vk = welcome.newsroom_verifying_key;
        fpf_verifying_key
            .verify(&newsroom_vk.into_bytes(), &welcome.fpf_sig)
            .map_err(|_| anyhow::anyhow!("invalid FPF signature on newsroom verifying key"))?;

        for journalist in welcome.journalists.iter() {
            Self::Protocol::verify_long_term(journalist, &newsroom_vk)?;
        }

        self.set_newsroom_verifying_key(newsroom_vk);

        // Example callback
        Self::Callback::on_result(());
        Ok(())
    }

    fn fetch_message(&self, message_id: Uuid) -> Result<(), Error> {
        let untrusted_msg = Self::NetworkApi::fetch_message(MessageFetchRequest { message_id })?;

        // Example callback
        Self::Callback::on_result(());
        Ok(())
    }

    fn fetch_challenges() -> Result<(), Error> {
        Self::NetworkApi::fetch_message_ids(MessageChallengeFetchRequest {})?;
        Ok(())
    }

    fn send_message(
        &self,
        untrustedinput: UntrustedInput<&[u8]>,
        sender: &impl UserSecret,
        recipient: &impl UserPublic,
    ) -> Result<(), Error> {
        // Placeholder, actual unwrap/sanitize/normalize should do something
        let input = untrustedinput.0;

        let env = Self::Protocol::encrypt_message(&mut self.rng(), input, sender, recipient)?;
        let resp = Self::NetworkApi::submit_message(env)?;

        Self::Callback::on_result(());
        Ok(())
    }
}

// Stub, handle untrusted input, eg via `sanitize(in: Untrusted<T>) -> T` function
pub struct UntrustedInput<T>(pub T);

// Data returned to the client application
pub struct ClientApplicationData<T> {
    pub data: Option<T>,
}
pub trait ApplicationCallback {
    // Should contain eg ClientApplicationData
    fn on_result(data: ());
}

// todo
type ProtocolError = anyhow::Error;

/// Protocol Definition. This is the boundary between the protocol and the enclosing application.
pub trait ClientProtocol {
    /// Encrypts and submits a message from `sender` to `recipient`.
    ///
    /// Handles padding, plaintext construction (including sender reply keys),
    /// and hybrid encryption. This covers step 6 (source submissions) and
    /// step 9 (journalist replies) in the protocol spec.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    fn encrypt_message<R, P, S>(
        rng: &mut R,
        message: &[u8],
        sender: &S,
        recipient: &P,
    ) -> Result<Envelope, ProtocolError>
    where
        R: RngCore + CryptoRng,
        P: UserPublic,
        S: UserSecret + ?Sized,
    {
        // TODO: review padding
        let padded_message = crate::schemes::pad::pad_message(message);
        let plaintext = sender.build_message(padded_message);
        let envelope = encrypt(rng, sender, &plaintext, recipient);
        Ok(envelope)
    }

    fn decrypt_message<P, S>(
        message: Envelope,
        sender: &S,
        recipient: &P,
    ) -> Result<(), ProtocolError> {
        // this should return everything that's needed:
        // Metadata, Message, SenderPublic, which keys were used, whatever is needed
        todo!("Unimplemented!")
    }

    fn verify_long_term(
        journalist: &JournalistLongTermView,
        newsroom_verifying_key: &VerifyingKey,
    ) -> Result<(), ProtocolError> {
        newsroom_verifying_key
            .verify(&journalist.vk.into_bytes(), &journalist.nr_signature)
            .map_err(|_| anyhow::anyhow!("invalid newsroom signature on journalist signing key"))?;
        journalist
            .vk
            .verify(
                &journalist.signed_longterm_key_bundle.bundle_bytes(),
                &journalist.signed_longterm_key_bundle.selfsig,
            )
            .map_err(|_| anyhow::anyhow!("invalid journalist self-signature on long-term keys"))?;
        Ok(())
    }

    fn verify_ephemeral_keys(
        roster: &[JournalistLongTermView],
        ephemeral: &[JournalistEphemeralKeys],
    ) -> Result<Vec<JournalistPublicView>, ProtocolError> {
        let mut views = Vec::new();
        let mut seen: Vec<[u8; 32]> = Vec::new();

        for eph in ephemeral {
            let vk = eph.vk.into_bytes();
            let Some(long_term) = roster.iter().find(|j| j.vk.into_bytes() == vk) else {
                continue; // Discard if no match in roster
            };
            if seen.contains(&vk) {
                return Err(anyhow::anyhow!(
                    "detected multiple ephemeral key bundles for the same journalist signing key"
                ));
            }
            seen.push(vk);

            let signed_bundle = &eph.ephemeral;
            long_term
                .vk
                .verify(&signed_bundle.0.as_bytes(), &signed_bundle.1)
                .map_err(|_| {
                    anyhow::anyhow!("invalid journalist self-signature on one-time keys")
                })?;

            views.push(JournalistPublicView::new(
                long_term.vk,
                long_term.signed_longterm_key_bundle.clone(),
                signed_bundle.clone(),
            ));
        }

        Ok(views)
    }

    /// Solves the encrypted message-ID challenges returned by the server.
    ///
    /// Each [`FetchResponse`] contains an encrypted message ID and a
    /// per-request DH share. The client uses its fetch keypair to recover
    /// message IDs that were addressed to it, discarding the rest.
    ///
    /// Returns the set of [`Uuid`]s for messages belonging to this client.
    fn solve_fetch_challenges<S>(
        recipient: &S,
        challenges: &[FetchResponse],
    ) -> Result<Vec<Uuid>, ProtocolError>
    where
        S: UserSecret + Sized,
    {
        Ok(solve_fetch_challenges(recipient, challenges))
    }
}

// Use default implementation
pub struct DefaultProtocol;
impl ClientProtocol for DefaultProtocol {}

// Example for now
type NetworkError = anyhow::Error;
enum ResponseStatus {}

/// Network [`Api`](Api) common to all users.
pub trait Api {
    /// Initial request made to the server to retrive instance-specific roster
    fn request_keys(req: WelcomeBundleRequest) -> Result<WelcomeBundle, NetworkError>;

    /// Creates a request to fetch encrypted message IDs from the server.
    ///
    /// Corresponds to step 7 in the protocol spec. The server returns a
    /// fixed-size set of challenges (encrypted message IDs) that the client
    /// must solve using [`solve_fetch_challenges`](Api::solve_fetch_challenges).
    fn fetch_message_ids(req: MessageChallengeFetchRequest)
    -> Result<ResponseStatus, NetworkError>;

    /// Creates a request to fetch a specific message by its ID.
    ///
    /// Corresponds to steps 8 and 10 in the protocol spec. Returns `None`
    /// if the request cannot be constructed (the default implementation
    /// always returns `Some`).
    fn fetch_message(
        req: MessageFetchRequest,
    ) -> Result<Option<UntrustedInput<Envelope>>, NetworkError>;

    fn submit_message(req: Envelope) -> Result<ResponseStatus, NetworkError>;
}

/// Journalist-specific API operations.
///
/// Extends [`Api`] with enrollment and ephemeral key management.
/// Restricted to implementors RestrictedApi trait and
/// the Enrollable trait. Implementors of both those will automatically be able to use
/// this generic JournalistApi implementation, but downstream crates will be unable to
/// implement RestrictedApi. Originally this was defined at the trait level
/// (`pub trait JournalistApi: Api + restricted::RestrictedApi`), but hax was unable
/// to extract the trait.
pub trait JournalistApi: Api + RestrictedApi {
    fn create_setup_request(setup: JournalistSetupRequest) -> Result<ResponseStatus, Error>;

    fn create_ephemeral_key_request(
        kr: JournalistEphemeralKeyRequest,
    ) -> Result<ResponseStatus, Error>;
}
