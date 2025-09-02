//! Source-side protocol implementation
//!
//! This module implements the source-side handling of SecureDrop protocol steps 5-10.
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

use crate::keys::{
    JournalistEnrollmentKeyBundle, JournalistEphemeralPublicKeys, SourceKeyBundle, SourcePassphrase,
};
use crate::messages::core::{
    Message, MessageChallengeFetchRequest, SourceJournalistKeyRequest, SourceJournalistKeyResponse,
    SourceMessage, SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
};
use crate::{Client, client::ClientPrivate};

use crate::sign::VerifyingKey;

/// Source session for interacting with the server
///
/// TODO: Load from storage
#[derive(Clone)]
pub struct SourceClient {
    /// Source's key bundle derived from passphrase
    key_bundle: Option<SourceKeyBundle>,
    /// Newsroom's verifying key (stored after verification)
    newsroom_verifying_key: Option<VerifyingKey>,
}

impl SourceClient {
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
}

impl Client for SourceClient {
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

impl ClientPrivate for SourceClient {
    fn fetching_private_key(&self) -> Result<[u8; 32], Error> {
        Ok(self
            .key_bundle
            .as_ref()
            .unwrap()
            .fetch
            .private_key
            .clone()
            .into_bytes())
    }
}

impl SourceClient {
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

            // 2. Use the shared method for encryption and message creation
            let request = self.submit_structured_message(
                source_message,
                (
                    &journalist_response.ephemeral_dh_pk,
                    &journalist_response.ephemeral_kem_pk,
                ),
                &journalist_response.ephemeral_pke_pk,
                &journalist_response.journalist_fetch_pk,
                &key_bundle.long_term_dh.private_key,
                &key_bundle.long_term_dh.public_key,
                rng,
            )?;

            requests.push(request);
        }

        Ok(requests)
    }
}
