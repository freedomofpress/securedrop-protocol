//! Journalist-side protocol implementation
//!
//! This module implements the journalist-side handling of SecureDrop protocol steps 7-9.

use crate::keys::{
    JournalistDHKeyPair, JournalistEnrollmentKeyBundle, JournalistEphemeralDHKeyPair,
    JournalistEphemeralKEMKeyPair, JournalistEphemeralKeyBundle, JournalistEphemeralPKEKeyPair,
    JournalistEphemeralPublicKeys, JournalistFetchKeyPair, JournalistSigningKeyPair,
};
use crate::messages::core::{MessageFetchResponse, MessageIdFetchResponse};
use crate::messages::setup::{JournalistRefreshRequest, JournalistSetupRequest};
use crate::sign::VerifyingKey;
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

/// Journalist session for interacting with the server
///
/// TODO: All this stuff should be persisted to disk.
pub struct JournalistSession {
    /// Journalist's long-term signing key pair
    signing_key: Option<JournalistSigningKeyPair>,
    /// Journalist's long-term fetching key pair
    fetching_key: Option<JournalistFetchKeyPair>,
    /// Journalist's long-term DH key pair
    dh_key: Option<JournalistDHKeyPair>,
    /// Generated ephemeral key pairs (for reuse)
    ephemeral_keys: Vec<JournalistEphemeralKeyBundle>,
}

impl JournalistSession {
    /// Create a new journalist session
    ///
    /// TODO: Load from storage
    pub fn new() -> Self {
        Self {
            signing_key: None,
            fetching_key: None,
            dh_key: None,
            ephemeral_keys: Vec::new(),
        }
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
        let dh_key = JournalistDHKeyPair::new(&mut rng);

        // Extract public keys before moving the key pairs
        let signing_vk = signing_key.vk;
        let fetching_pk = fetching_key.public_key.clone();
        let dh_pk = dh_key.public_key.clone();

        // Store the generated keys in the session
        self.signing_key = Some(signing_key);
        self.fetching_key = Some(fetching_key);
        self.dh_key = Some(dh_key);

        // Create enrollment key bundle with public keys
        let enrollment_key_bundle = JournalistEnrollmentKeyBundle {
            signing_key: signing_vk,
            fetching_key: fetching_pk,
            dh_key: dh_pk,
        };

        // Create setup request with the enrollment key bundle
        Ok(JournalistSetupRequest {
            enrollment_key_bundle,
        })
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
        // Get the signing key from the session
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No signing key found in session. Call create_setup_request first.")
        })?;

        // Generate ephemeral key pairs
        let ephemeral_dh = JournalistEphemeralDHKeyPair::new(&mut rng);
        let ephemeral_kem = JournalistEphemeralKEMKeyPair::new(&mut rng);
        let ephemeral_pke = JournalistEphemeralPKEKeyPair::new(&mut rng);

        // Extract public keys
        let ephemeral_dh_pubkey = ephemeral_dh.public_key;
        let ephemeral_kem_pubkey = ephemeral_kem.public_key;
        let ephemeral_pke_pubkey = ephemeral_pke.public_key;

        // Create ephemeral public keys struct for signing
        let ephemeral_public_keys = JournalistEphemeralPublicKeys {
            edh_pk: ephemeral_dh_pubkey,
            ekem_pk: ephemeral_kem_pubkey,
            epke_pk: ephemeral_pke_pubkey,
        };

        // Create the ephemeral key bundle
        let ephemeral_key_bundle = JournalistEphemeralKeyBundle {
            public_keys: ephemeral_public_keys.clone(),
            signature: signing_key.sign(&ephemeral_public_keys.into_bytes()),
        };

        // Store the ephemeral key bundle in the session
        self.ephemeral_keys.push(ephemeral_key_bundle.clone());

        Ok(JournalistRefreshRequest {
            journalist_verifying_key: signing_key.vk,
            ephemeral_key_bundle,
        })
    }

    /// Get the journalist's verifying key from the session
    pub fn verifying_key(&self) -> Option<&VerifyingKey> {
        self.signing_key.as_ref().map(|sk| &sk.vk)
    }

    /// Fetch message IDs (step 7)
    pub fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageIdFetchResponse {
        // TODO: Implement message ID fetching
        unimplemented!()
    }

    /// Fetch a specific message (step 8)
    pub fn fetch_message(&self, _message_id: u64) -> Option<MessageFetchResponse> {
        // TODO: Implement HTTP request to server
        unimplemented!()
    }

    /// Reply to a source (step 9)
    pub fn reply_to_source<R: RngCore + CryptoRng>(
        &self,
        _message: Vec<u8>,
        _rng: &mut R,
    ) -> Result<(), Error> {
        // TODO: Implement message encryption
        unimplemented!()
    }
}
