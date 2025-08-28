//! Source-side protocol implementation
//!
//! This module implements the source-side handling of SecureDrop protocol steps 5-10.
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::keys::{
    JournalistEnrollmentKeyBundle, JournalistEphemeralPublicKeys, SourceKeyBundle, SourcePassphrase,
};
use crate::messages::core::{
    Message, MessageChallengeFetchRequest, MessageChallengeFetchResponse, MessageFetchResponse,
    SourceJournalistKeyRequest, SourceJournalistKeyResponse, SourceMessage,
    SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
};
use crate::primitives::{decrypt_message_id, dh_public_key_from_scalar, dh_shared_secret};

use crate::sign::VerifyingKey;

/// Source session for interacting with the server
///
/// TODO: Load from storage
#[derive(Clone)]
pub struct SourceSession {
    /// Source's key bundle derived from passphrase
    key_bundle: Option<SourceKeyBundle>,
    /// Newsroom's verifying key (stored after verification)
    newsroom_verifying_key: Option<VerifyingKey>,
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
            newsroom_verifying_key: None,
        };

        (passphrase, session)
    }

    /// Initialize source session from existing passphrase (Protocol Step 4)
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        let key_bundle = SourceKeyBundle::from_passphrase(passphrase);

        Self {
            key_bundle: Some(key_bundle),
            newsroom_verifying_key: None,
        }
    }

    /// Get the source's key bundle
    pub fn key_bundle(&self) -> Option<&SourceKeyBundle> {
        self.key_bundle.as_ref()
    }

    /// Get the newsroom's verifying key
    pub fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.newsroom_verifying_key.as_ref()
    }

    /// Get the newsroom's verifying key, returning an error if not available
    pub fn get_newsroom_verifying_key(&self) -> Result<&VerifyingKey, Error> {
        self.newsroom_verifying_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Newsroom verifying key not available"))
    }

    /// Fetch newsroom keys (step 5)
    pub fn fetch_newsroom_keys(&self) -> SourceNewsroomKeyRequest {
        SourceNewsroomKeyRequest {}
    }

    /// Handle and verify newsroom key response (step 5)
    ///
    /// This verifies the FPF signature on the newsroom's verifying key
    /// and stores the verified key in the session.
    pub fn handle_newsroom_key_response(
        &mut self,
        response: &SourceNewsroomKeyResponse,
        fpf_verifying_key: &VerifyingKey,
    ) -> Result<(), Error> {
        // Verify the FPF signature on the newsroom's verifying key
        let newsroom_vk_bytes = response.newsroom_verifying_key.into_bytes();
        fpf_verifying_key
            .verify(&newsroom_vk_bytes, &response.fpf_sig)
            .map_err(|_| anyhow::anyhow!("Invalid FPF signature on newsroom verifying key"))?;

        // Store the verified newsroom verifying key
        self.newsroom_verifying_key = Some(response.newsroom_verifying_key);

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
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let key_bundle = self
            .key_bundle
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Source key bundle not initialized"))?;

        let mut requests = Vec::new();

        // Submit a distinct copy of the message to each journalist
        for journalist_response in journalist_responses {
            // 1. Create the structured message according to Step 6 format:
            // msg || S_dh,pk || S_pke,pk || S_kem,pk || S_fetch,pk || J^i_sig,pk || NR
            let source_message = SourceMessage {
                message: message.clone(),
                source_dh_pk: key_bundle.long_term_dh.public_key.clone(),
                source_pke_pk: key_bundle.pke.public_key.clone(),
                source_kem_pk: key_bundle.kem.public_key.clone(),
                source_fetch_pk: key_bundle.fetch.public_key.clone(),
                journalist_sig_pk: journalist_response.journalist_sig_pk,
                newsroom_sig_pk: self.get_newsroom_verifying_key()?.clone(),
            };

            // 2. Create the padded message
            let padded_message = crate::primitives::pad_message(&source_message.into_bytes());

            // 3. Perform authenticated encryption
            let ((c1, c2), c_double_prime) = crate::primitives::auth_encrypt(
                &key_bundle.long_term_dh.private_key,
                (
                    &journalist_response.ephemeral_dh_pk,
                    &journalist_response.ephemeral_kem_pk,
                ),
                &padded_message,
            )?;

            // 4. Encrypt the DH key and ciphertexts
            let c_prime = crate::primitives::enc(
                &journalist_response.ephemeral_pke_pk,
                key_bundle.dh_public_key(),
                &c1,
                &c2,
            )?;

            // 5. Combine ciphertexts
            let ciphertext = [c_prime, c_double_prime].concat();

            // 6. Generate DH shares
            let x_bytes = crate::primitives::generate_random_scalar(rng)
                .map_err(|e| anyhow::anyhow!("Failed to generate random scalar: {}", e))?;
            let x_share = crate::primitives::dh_public_key_from_scalar(x_bytes);
            let z_share = crate::primitives::dh_shared_secret(
                &journalist_response.journalist_fetch_pk,
                x_bytes,
            );

            // 7. Create message submit request
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
    pub fn fetch_message_ids(&self) -> MessageChallengeFetchRequest {
        MessageChallengeFetchRequest {}
    }

    /// Process message ID fetch response (step 7)
    ///
    /// TODO: Share logic with journalist.rs
    pub fn process_message_id_response(
        &self,
        response: &MessageChallengeFetchResponse,
    ) -> Result<Vec<Uuid>, Error> {
        let mut message_ids = Vec::new();
        let fetching_secret_key = self.key_bundle.as_ref().unwrap().fetch.private_key.clone();

        // Process each (Q_i, cid_i) pair
        for (q_i, cid_i) in &response.messages {
            // k_i = DH(Q_i, U_fetch,sk)
            let q_public_key =
                dh_public_key_from_scalar(q_i.clone().try_into().unwrap_or([0u8; 32]));
            let k_i = dh_shared_secret(&q_public_key, fetching_secret_key.clone().into_bytes())
                .into_bytes();

            // Decrypt message ID: id_i = Dec(k_i, cid_i)
            match decrypt_message_id(&k_i, cid_i) {
                Ok(decrypted_id) => {
                    // Try to parse as UUID
                    if decrypted_id.len() == 16 {
                        if let Ok(id_bytes) = decrypted_id.try_into() {
                            let uuid = Uuid::from_bytes(id_bytes);
                            message_ids.push(uuid);
                        }
                    }
                }
                Err(_) => {
                    // Decryption failed, this is a random entry
                }
            }
        }

        Ok(message_ids)
    }

    /// Fetch a specific message (step 10)
    pub fn fetch_message(&self, _message_id: u64) -> Option<MessageFetchResponse> {
        unimplemented!()
    }
}
