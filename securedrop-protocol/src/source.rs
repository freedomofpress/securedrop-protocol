//! Source-side protocol implementation
//!
//! This module implements the source-side handling of SecureDrop protocol steps 5-10.

use crate::keys::{
    JournalistEnrollmentKeyBundle, JournalistEphemeralPublicKeys, SourceKeyBundle, SourcePassphrase,
};
use crate::messages::core::{
    Message, MessageChallengeFetchResponse, MessageFetchResponse, SourceJournalistKeyRequest,
    SourceJournalistKeyResponse, SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
};
use crate::sign::VerifyingKey;
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

/// Source session for interacting with the server
///
/// TODO: Load from storage
#[derive(Debug, Clone)]
pub struct SourceSession {
    /// Source's key bundle derived from passphrase
    key_bundle: Option<SourceKeyBundle>,
}

impl SourceSession {
    /// Initialize source session with keys derived from passphrase (Protocol Step 4)
    pub fn initialize_with_passphrase<R: RngCore + CryptoRng>(
        mut rng: R,
    ) -> (SourcePassphrase, Self) {
        // Generate a new source key bundle with random passphrase
        let (passphrase, key_bundle) = SourceKeyBundle::new(&mut rng);

        let session = Self {
            key_bundle: Some(key_bundle),
        };

        (passphrase, session)
    }

    /// Initialize source session from existing passphrase (Protocol Step 4)
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        let key_bundle = SourceKeyBundle::from_passphrase(passphrase);

        Self {
            key_bundle: Some(key_bundle),
        }
    }

    /// Get the source's key bundle
    pub fn key_bundle(&self) -> Option<&SourceKeyBundle> {
        self.key_bundle.as_ref()
    }

    /// Fetch newsroom keys (step 5)
    pub fn fetch_newsroom_keys(&self) -> SourceNewsroomKeyRequest {
        SourceNewsroomKeyRequest {}
    }

    /// Handle and verify newsroom key response (step 5)
    ///
    /// This verifies the FPF signature on the newsroom's verifying key.
    pub fn handle_newsroom_key_response(
        &self,
        response: &SourceNewsroomKeyResponse,
        fpf_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        // Verify the FPF signature on the newsroom's verifying key
        let newsroom_vk_bytes = response.newsroom_verifying_key.into_bytes();
        fpf_verifying_key
            .verify(&newsroom_vk_bytes, &response.fpf_sig)
            .map_err(|_| anyhow::anyhow!("Invalid FPF signature on newsroom verifying key"))?;

        Ok(())
    }

    /// Fetch journalist keys (step 5)
    pub fn fetch_journalist_keys(&self) -> SourceJournalistKeyRequest {
        SourceJournalistKeyRequest {}
    }

    /// Handle and verify journalist key response (step 5)
    ///
    /// This verifies the newsroom signature on the journalist's keys
    /// and the journalist signature on the ephemeral keys.
    pub fn handle_journalist_key_response(
        &self,
        response: &SourceJournalistKeyResponse,
        newsroom_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        // Create the enrollment bundle that was signed by the newsroom
        let enrollment_bundle = JournalistEnrollmentKeyBundle {
            signing_key: response.journalist_sig_pk,
            fetching_key: response.journalist_fetch_pk.clone(),
            dh_key: response.journalist_dh_pk.clone(),
        };

        // Verify the newsroom signature on the journalist's enrollment bundle
        newsroom_verifying_key
            .verify(&enrollment_bundle.into_bytes(), &response.newsroom_sig)
            .map_err(|_| anyhow::anyhow!("Invalid newsroom signature on journalist keys"))?;

        // Create the ephemeral keys that were signed by the journalist
        let ephemeral_keys = JournalistEphemeralPublicKeys {
            edh_pk: response.ephemeral_dh_pk.clone(),
            ekem_pk: response.ephemeral_kem_pk.clone(),
            epke_pk: response.ephemeral_pke_pk.clone(),
        };

        // Verify the journalist signature on the ephemeral keys
        response
            .journalist_sig_pk
            .verify(
                &ephemeral_keys.into_bytes(),
                &response.journalist_ephemeral_sig,
            )
            .map_err(|_| anyhow::anyhow!("Invalid journalist signature on ephemeral keys"))?;

        Ok(())
    }

    /// Submit a message (step 6)
    /// TODO: Consolidate with the procedure for replying to a message from a journalist?
    pub fn submit_message<R: RngCore + CryptoRng>(
        &self,
        message: Vec<u8>,
        journalist_responses: &[SourceJournalistKeyResponse],
        newsroom_verifying_key: &VerifyingKey,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let key_bundle = self
            .key_bundle
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Source key bundle not initialized"))?;

        let mut requests = Vec::new();

        // Submit a distinct copy of the message to each journalist
        for journalist_response in journalist_responses {
            // 1. Create the padded message
            let padded_message = crate::primitives::pad_message(&message);

            // 2. Perform authenticated encryption
            let ((c1, c2), c_double_prime) = crate::primitives::auth_encrypt(
                &key_bundle.long_term_dh.private_key,
                (
                    &journalist_response.ephemeral_dh_pk,
                    &journalist_response.ephemeral_kem_pk,
                ),
                &padded_message,
            )?;

            // 3. Encrypt the DH key and ciphertexts
            let c_prime = crate::primitives::enc(
                &journalist_response.ephemeral_pke_pk,
                key_bundle.dh_public_key(),
                &c1,
                &c2,
            )?;

            // 4. Combine ciphertexts
            let ciphertext = [c_prime, c_double_prime].concat();

            // 5. Generate DH shares
            let x_bytes = crate::primitives::generate_random_scalar(rng)
                .map_err(|e| anyhow::anyhow!("Failed to generate random scalar: {}", e))?;
            let x_share = crate::primitives::dh_public_key_from_scalar(x_bytes);
            let z_share = crate::primitives::dh_shared_secret(
                &journalist_response.journalist_fetch_pk,
                x_bytes,
            );

            // 6. Create message submit request
            let request = Message {
                ciphertext,
                dh_share_z: z_share.into_bytes().to_vec(),
                dh_share_x: x_share.into_bytes().to_vec(),
            };

            requests.push(request);
        }

        Ok(requests)
    }

    /// Fetch message IDs (step 7)
    pub fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageChallengeFetchResponse {
        unimplemented!()
    }

    /// Fetch a specific message (step 10)
    pub fn fetch_message(&self, _message_id: u64) -> Option<MessageFetchResponse> {
        unimplemented!()
    }
}
