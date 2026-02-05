use crate::{
    Signature, VerifyingKey,
    encrypt_decrypt::{encrypt, solve_fetch_challenges},
    messages::{
        core::{
            MessageChallengeFetchRequest, MessageFetchRequest, SourceJournalistKeyRequest,
            SourceJournalistKeyResponse, SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
        },
        setup::{JournalistRefreshRequest, JournalistSetupRequest},
    },
    types::{
        Enrollable, Envelope, FetchResponse, JournalistPublic, SignedKeyBundlePublic, UserPublic,
        UserSecret,
    },
};
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

/// Common client functionality for source and journalist clients
pub trait Api {
    /// Get the newsroom's verifying key
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey>;

    /// Set the newsroom's verifying key
    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey);

    /// actions
    // todo rename
    fn fetch_newsroom_keys(&self) -> SourceNewsroomKeyRequest {
        SourceNewsroomKeyRequest {}
    }

    fn fetch_journalist_keys(&self) -> SourceJournalistKeyRequest {
        SourceJournalistKeyRequest {}
    }

    /// Fetch message IDs (step 7)
    fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageChallengeFetchRequest {
        MessageChallengeFetchRequest {}
    }

    fn solve_fetch_challenges(
        &self,
        challenges: Vec<FetchResponse>,
    ) -> Result<Vec<Uuid>, anyhow::Error>
    where
        Self: Sized + UserSecret,
    {
        Ok(solve_fetch_challenges(self, challenges))
    }

    /// Fetch a specific message (step 8)
    fn fetch_message(&self, message_id: Uuid) -> Option<MessageFetchRequest> {
        Some(MessageFetchRequest { message_id })
    }

    /// Submit a structured message (step 6 for sources, step 9 for journalists)
    ///
    /// This is a generic method that handles both source message submission and journalist replies.
    /// The specific message structure and encryption details are provided by the implementing types.
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
        // TODO review padding
        let padded_message = crate::primitives::pad::pad_message(&message);

        let plaintext = sender.build_message(padded_message);

        let env = encrypt(rng, sender, plaintext, recipient);

        Ok(env)
    }

    /// source stuff TODO
    fn handle_newsroom_key_response(
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
        let _ = &self.set_newsroom_verifying_key(response.newsroom_verifying_key);

        Ok(())
    }

    fn handle_journalist_key_response(
        &self,
        response: &SourceJournalistKeyResponse,
        newsroom_verifying_key: &VerifyingKey,
        // fpf_verifying_key: &VerifyingKey,
        // fpf_signature: &Signature,
    ) -> Result<(), Error> {
        // Verify the newsroom signature on the journalist's signing key
        newsroom_verifying_key
            .verify(
                &response.journalist.verifying_key().into_bytes(),
                &response.nr_signature,
            )
            .map_err(|_| anyhow::anyhow!("Invalid newsroom signature on journalist signing key"))?;

        // Verify the journalist's signature on their long-term key bundle
        let enrollment_signature = &response.journalist.self_signature().as_signature();
        let enrollment_msg = response.journalist.signed_keybytes();

        response
            .journalist
            .verifying_key()
            .verify(&enrollment_msg.0, enrollment_signature)
            .map_err(|_| anyhow::anyhow!("Invalid self-signature on journalist lt keys"))?;

        // Verify the self-signature on the one-time keys
        response
            .journalist
            .verifying_key()
            .verify(
                &response.journalist.signed_keybytes().0,
                &response.journalist.self_signature().as_signature(),
            )
            .map_err(|_| anyhow::anyhow!("Invalid journalist signature on one-time keys"))?;

        Ok(())
    }
}

pub(crate) mod restricted {
    pub trait RestrictedApi {}
}

pub trait JournalistApi: Api + restricted::RestrictedApi {
    fn create_setup_request(&self) -> Result<JournalistSetupRequest, Error>
    where
        Self: Enrollable,
    {
        Ok(JournalistSetupRequest {
            enrollment: self.enroll(),
        })
    }

    fn create_ephemeral_key_request(&self) -> Result<JournalistRefreshRequest, Error>
    where
        Self: Enrollable,
    {
        // todo new keys later

        // Store the ephemeral key bundle in the session
        // TODO: maybe store the whole keybundle including signature?
        let bundles: Vec<SignedKeyBundlePublic> = self.signed_keybundles().collect();

        Ok(JournalistRefreshRequest {
            vk: self.signing_key().clone(),
            bundles: bundles,
            bundle_sig: Signature([0u8; 64]), // TODO!!- right now each bundle is signed not the whole bundle....
        })
    }
}
