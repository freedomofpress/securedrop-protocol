//! Journalist-side protocol implementation
//!
//! This module implements the journalist-side handling of SecureDrop protocol steps 7-9.
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::Signature;
use crate::keys::{
    JournalistDHKeyPair, JournalistEphemeralDHKeyPair, JournalistEphemeralKEMKeyPair,
    JournalistEphemeralPKEKeyPair, JournalistFetchKeyPair, JournalistOneTimeKeyBundle,
    JournalistOneTimeKeypairs, JournalistOneTimePublicKeys, JournalistSigningKeyPair,
};
use crate::keys::{JournalistEnrollmentKeyBundle, SourcePublicKeys};
use crate::messages::core::{JournalistReplyMessage, Message, MessageChallengeFetchRequest};
use crate::messages::setup::{JournalistRefreshRequest, JournalistSetupRequest};
use crate::primitives::x25519::DHPublicKey;
use crate::sign::VerifyingKey;
use crate::{Client, client::ClientPrivate};

/// Journalist session for interacting with the server
///
/// TODO: All this stuff should be persisted to disk.
#[derive(Default)]
pub struct JournalistClient {
    /// Journalist's long-term signing key pair
    signing_key: Option<JournalistSigningKeyPair>,
    /// Journalist's long-term fetching key pair
    fetching_key: Option<JournalistFetchKeyPair>,
    /// Journalist's long-term DH key pair
    /// TODO: Remove? Not for use with encryption, although it
    /// may be needed as "key of last resort" - to discuss
    dh_key: Option<JournalistDHKeyPair>,
    /// and use instead of dh_key for encryption
    /// Journalist one-time keypairs
    one_time_keystore: Vec<JournalistOneTimeKeypairs>,
    /// Newsroom's verifying key
    newsroom_verifying_key: Option<VerifyingKey>,
}

impl JournalistClient {
    /// Create a new journalist session
    ///
    /// TODO: Load from storage
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a new journalist setup request.
    ///
    /// This generates the journalist's key pairs and creates a setup request
    /// containing only the public keys to send to the newsroom.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn create_setup_request<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
    ) -> Result<JournalistSetupRequest, Error> {
        // Generate journalist key pairs
        let signing_key = JournalistSigningKeyPair::new(&mut rng);
        let fetching_key = JournalistFetchKeyPair::new(&mut rng);

        // Extract public keys before moving the key pairs
        let signing_vk = signing_key.vk;
        let fetching_pk = fetching_key.public_key.clone();

        // Store the generated keys in the session
        self.signing_key = Some(signing_key);
        self.fetching_key = Some(fetching_key);

        // Create enrollment key bundle with public keys
        let enrollment_key_bundle = JournalistEnrollmentKeyBundle {
            signing_key: signing_vk,
            fetching_key: fetching_pk,
        };

        // Create setup request with the enrollment key bundle
        Ok(JournalistSetupRequest {
            enrollment_key_bundle,
        })
    }

    /// Sign a message.
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No signing key found in session. Call create_setup_request first.")
        })?;

        Ok(signing_key.sign(message))
    }

    /// Generate a new ephemeral key refresh request.
    ///
    /// This generates ephemeral key pairs and creates a request containing
    /// the ephemeral public keys signed by the journalist's signing key.
    ///
    /// Step 3.2 in the spec.
    pub fn create_ephemeral_key_request<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
    ) -> Result<JournalistRefreshRequest, Error> {
        let key_bundle = JournalistOneTimeKeypairs::generate(&mut rng);

        let one_time_pubkey_bundle = JournalistOneTimeKeyBundle {
            public_keys: key_bundle.pubkeys().clone(),
            signature: self.sign(&key_bundle.pubkeys().into_bytes())?,
        };

        // Store the ephemeral key bundle in the session
        self.one_time_keystore.push(key_bundle.clone());

        Ok(JournalistRefreshRequest {
            journalist_verifying_key: self
                .verifying_key()
                .expect("Signing key should be set at this point")
                .clone(),
            ephemeral_key_bundle: one_time_pubkey_bundle,
        })
    }

    /// Get the journalist's verifying key
    pub fn verifying_key(&self) -> Option<&VerifyingKey> {
        self.signing_key.as_ref().map(|sk| &sk.vk)
    }

    /// Get the journalist's fetching key
    pub fn fetching_key(&self) -> Option<&DHPublicKey> {
        self.fetching_key.as_ref().map(|fk| &fk.public_key)
    }

    /// Get the journalist's long-term DH key
    /// TODO: keeping? (Key of last resort?)
    /// This is not the key that should be used for message encryption!
    /// Message encrpytion uses a one-time DH-AKEM key.
    /// We shouldn't use this anywhere for now.
    #[deprecated]
    pub fn dh_key(&self) -> Option<&DHPublicKey> {
        self.dh_key.as_ref().map(|dk| &dk.public_key)
    }
}

impl Client for JournalistClient {
    type NewsroomKey = VerifyingKey;

    fn newsroom_verifying_key(&self) -> Option<&Self::NewsroomKey> {
        self.newsroom_verifying_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: Self::NewsroomKey) {
        self.newsroom_verifying_key = Some(key);
    }

    fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageChallengeFetchRequest {
        MessageChallengeFetchRequest {}
    }
}

impl ClientPrivate for JournalistClient {
    fn fetching_private_key(&self) -> Result<[u8; 32], Error> {
        Ok(self
            .fetching_key
            .as_ref()
            .expect("Fetching key in session")
            .private_key
            .clone()
            .into_bytes())
    }
}

impl JournalistClient {
    /// Reply to a source (step 9)
    ///
    /// This is similar to Step 6 (source message submission) but from the journalist's perspective.
    /// The journalist encrypts a message for a specific source using the source's public keys.
    pub fn reply_to_source<R: RngCore + CryptoRng>(
        &self,
        message: Vec<u8>,
        source_public_keys: &SourcePublicKeys,
        source: Uuid,
        newsroom_signature: crate::sign::Signature,
        rng: &mut R,
    ) -> Result<Message, Error> {
        // Get the journalist's DH private key
        // TODO: not the long-term DH key!
        let journalist_dhakem_keypair: JournalistEphemeralDHKeyPair = "";

        let journalist_dh_private_key = self
            .dh_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No DH key found in session"))?
            .private_key
            .clone();

        // 1. Create the structured message according to Step 9 format:
        // TODO format needs revising; PQ_KEM_PSK key?
        // msg || S || J_sig,pk || J_fetch,pk || J_dh,pk || σ^NR || NR
        let journalist_reply_message = JournalistReplyMessage {
            message,
            source,
            journalist_sig_pk: self.signing_key.as_ref().unwrap().vk,
            journalist_fetch_pk: self.fetching_key.as_ref().unwrap().public_key.clone(),
            journalist_dh_pk: self.dh_key.as_ref().unwrap().public_key.clone(),
            newsroom_signature,
            newsroom_sig_pk: *self.get_newsroom_verifying_key()?,
        };

        // 2. Use the shared method for encryption and message creation
        self.submit_structured_message(
            journalist_reply_message,
            (
                &source_public_keys.message_dhakem_pk,
                &source_public_keys.message_pq_psk_pk,
            ),
            &source_public_keys.metadata_pk,
            &source_public_keys.fetch_pk,
            &journalist_dh_private_key,
            &self.dh_key.as_ref().unwrap().public_key,
            rng,
        )
    }
}
