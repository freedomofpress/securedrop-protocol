//! Source-side protocol implementation
//!
//! This module implements the source-side handling of SecureDrop protocol steps 5-10.
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

use crate::keys::{
    JournalistEnrollmentKeyBundle, JournalistLongtermPublicKeys, JournalistOneTimePublicKeys,
    SourceKeyBundle, SourcePassphrase,
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
    fn message_enc_private_key_dhakem(&self) -> Result<[u8; 32], Error> {
        Ok(*self
            .key_bundle
            .as_ref()
            .unwrap()
            .message_encrypt_dhakem
            .private_key
            .clone()
            .as_bytes())
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
        // Verify the newsroom signature on the journalist's signing key
        newsroom_verifying_key
            .verify(
                &response.journalist_sig_pk.into_bytes(),
                &response.newsroom_sig,
            )
            .map_err(|_| anyhow::anyhow!("Invalid newsroom signature on journalist keys"))?;

        // Reconstruct journalist self-signed long-term pubkey bundle
        let public_keys = JournalistLongtermPublicKeys {
            reply_key: response.journalist_dhakem_sending_pk.clone(),
            fetch_key: response.journalist_fetch_pk.clone(),
        };

        let enrollment_bundle = JournalistEnrollmentKeyBundle {
            signing_key: response.journalist_sig_pk,
            public_keys: public_keys,
            self_signature: response.journalist_self_sig.clone(),
        };

        let enrollment_signature = &enrollment_bundle.self_signature.clone().as_signature();

        // Verify the journalist's signature on their long-term key bundle
        enrollment_bundle
            .signing_key
            .verify(
                &enrollment_bundle.public_keys.into_bytes(),
                enrollment_signature,
            )
            .map_err(|_| anyhow::anyhow!("Invalid self-signature on journalist keys"))?;

        // Create the one-time keys that were signed by the journalist
        let one_time_keys = JournalistOneTimePublicKeys {
            one_time_message_pq_pk: response.one_time_message_pq_pk.clone(),
            one_time_message_pk: response.one_time_message_pk.clone(),
            one_time_metadata_pk: response.one_time_metadata_pk.clone(),
        };

        // Verify the self-signature on the one-time keys
        response
            .journalist_sig_pk
            .verify(
                &one_time_keys.into_bytes(),
                &response.journalist_ephemeral_sig,
            )
            .map_err(|_| anyhow::anyhow!("Invalid journalist signature on one-time keys"))?;

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
            let source_message = SourceMessage {
                message: message.clone(),
                source_message_pq_pk: key_bundle.pq_kem_psk.public_key.clone(),
                source_message_pk: key_bundle.message_encrypt_dhakem.public_key.clone(),
                source_metadata_pk: key_bundle.metadata.public_key.clone(),
                source_fetch_pk: key_bundle.fetch.public_key.clone(),
                journalist_sig_pk: journalist_response.journalist_sig_pk,
                newsroom_sig_pk: self.get_newsroom_verifying_key()?.clone(),
            };

            // Use the shared method for encryption and message creation
            let request = self.submit_structured_message(
                source_message,
                (
                    &journalist_response.one_time_message_pk,
                    &journalist_response.one_time_message_pq_pk,
                ),
                &journalist_response.one_time_metadata_pk,
                &journalist_response.journalist_fetch_pk,
                &key_bundle.message_encrypt_dhakem.private_key,
                &key_bundle.message_encrypt_dhakem.public_key,
                rng,
            )?;

            requests.push(request);
        }

        Ok(requests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_initialize_with_passphrase() {
        // Fixed seed RNG
        let rng = ChaCha20Rng::seed_from_u64(666);

        let (source1, session1) = SourceClient::initialize_with_passphrase(rng.clone());
        let (source2, session2) = SourceClient::initialize_with_passphrase(rng);

        assert_eq!(
            source1.passphrase, source2.passphrase,
            "Expected identical passphrase"
        );

        let keybundle1 = session1.key_bundle.expect("Should be keybundle");
        let keybundle2 = session2.key_bundle.expect("Should be keybundle");

        // DH keys
        assert_eq!(
            keybundle1.message_encrypt_dhakem.public_key.as_bytes(),
            keybundle2.message_encrypt_dhakem.public_key.as_bytes(),
            "DH Pubkey should be identical"
        );
        assert_eq!(
            keybundle1.message_encrypt_dhakem.private_key.as_bytes(),
            keybundle2.message_encrypt_dhakem.private_key.as_bytes(),
            "DH Private Key should be identical"
        );

        // PQ KEM keys
        assert_eq!(
            keybundle1.pq_kem_psk.public_key.as_bytes(),
            keybundle2.pq_kem_psk.public_key.as_bytes(),
            "PQ KEM Public Key should be identical"
        );
        assert_eq!(
            keybundle1.pq_kem_psk.private_key.as_bytes(),
            keybundle2.pq_kem_psk.private_key.as_bytes(),
            "PQ KEM Private Key should be identical"
        );

        // Metadata keys
        assert_eq!(
            keybundle1.metadata.public_key.as_bytes(),
            keybundle2.metadata.public_key.as_bytes(),
            "Metadata Public Key should be identical"
        );
        assert_eq!(
            keybundle1.metadata.private_key.as_bytes(),
            keybundle2.metadata.private_key.as_bytes(),
            "Metadata Private Key should be identical"
        );
    }
}
