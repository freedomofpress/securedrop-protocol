//! Server-side protocol implementation
//!
//! This module implements the server-side handling of SecureDrop protocol steps 5-10.

use alloc::vec::Vec;
use anyhow::{Error, anyhow};
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::keys::NewsroomKeyPair;
use crate::messages::core::{
    Message, MessageChallengeFetchRequest, MessageChallengeFetchResponse, MessageFetchRequest,
    MessageFetchResponse, SourceJournalistKeyRequest, SourceJournalistKeyResponse,
    SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
};
use crate::messages::setup::{
    JournalistRefreshRequest, JournalistRefreshResponse, JournalistSetupRequest,
    JournalistSetupResponse, NewsroomSetupRequest,
};
use crate::primitives::{
    MESSAGE_ID_FETCH_SIZE, encrypt_message_id,
    x25519::{dh_public_key_from_scalar, dh_shared_secret, generate_random_scalar},
};
use crate::sign::{Signature, VerifyingKey};
use crate::storage::ServerStorage;

/// Server session for handling source requests
#[derive(Default)]
pub struct Server {
    storage: ServerStorage,
    newsroom_keys: Option<NewsroomKeyPair>,
    /// Signature from FPF over the newsroom keys
    signature: Option<Signature>,
}

impl Server {
    /// Create a new server session
    ///
    /// TODO: Load newsroom keys from storage if they exist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a new newsroom setup request.
    ///
    /// This creates a newsroom key pair, stores it in the server storage,
    /// and returns a setup request that can be sent to FPF for signing.
    ///
    /// TODO: The caller should persist these keys to disk.
    pub fn create_newsroom_setup_request<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
    ) -> Result<NewsroomSetupRequest, Error> {
        let newsroom_keys = NewsroomKeyPair::new(&mut rng);
        let newsroom_vk = newsroom_keys.vk;

        // Store the newsroom keys in the session for later use (e.g., signing journalist keys)
        self.newsroom_keys = Some(newsroom_keys);

        Ok(NewsroomSetupRequest {
            newsroom_verifying_key: newsroom_vk,
        })
    }

    /// Setup a journalist. This corresponds to step 3.1 in the spec.
    ///
    /// The newsroom then signs the bundle of journalist public keys.
    ///
    /// TODO: There is a manual verification step here, so the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    ///
    /// TODO(later): How to handle signing when offline? (Not relevant for benchmarking)
    pub fn setup_journalist(
        &mut self,
        request: JournalistSetupRequest,
    ) -> Result<JournalistSetupResponse, Error> {
        // Get enrollment key bundle bytes from the request
        let enrollment_key_bundle_bytes = request.enrollment_key_bundle.clone().into_bytes();

        // Sign the journalist bundle
        let newsroom_keys = self
            .newsroom_keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Newsroom keys not found in session"))?;
        let newsroom_signature = newsroom_keys.sk.sign(&enrollment_key_bundle_bytes);

        // Insert journalist keys into storage
        let _journalist_id = self
            .storage
            .add_journalist(request.enrollment_key_bundle, newsroom_signature.clone());

        Ok(JournalistSetupResponse {
            sig: newsroom_signature,
        })
    }

    /// Handle journalist ephemeral key replenishment. This corresponds to step 3.2 in the spec.
    ///
    /// The journalist sends ephemeral keys signed by their signing key, and the server
    /// verifies the signature and stores the ephemeral keys.
    pub fn handle_ephemeral_key_request(
        &mut self,
        request: JournalistRefreshRequest,
    ) -> Result<JournalistRefreshResponse, Error> {
        let bundle = request.ephemeral_key_bundle;

        // Get the ephemeral public keys from the bundle
        let ephemeral_public_keys = &bundle.public_keys;

        // Create the message that was signed
        let signed_message = ephemeral_public_keys.clone().into_bytes();

        // Look up the journalist by their verifying key
        let journalist_id = self
            .storage
            .find_journalist_by_verifying_key(&request.journalist_verifying_key)
            .ok_or_else(|| anyhow::anyhow!("Journalist not found in storage"))?;

        // Verify the signature using the journalist's verifying key
        request
            .journalist_verifying_key
            .verify(&signed_message, &bundle.signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature on ephemeral keys"))?;

        // Store the ephemeral keys for the journalist
        self.storage
            .add_ephemeral_keys(journalist_id, Vec::from([bundle]));

        Ok(JournalistRefreshResponse { success: true })
    }

    /// Get the newsroom verifying key
    pub fn get_newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.newsroom_keys.as_ref().map(|keys| &keys.vk)
    }

    /// Set the FPF signature for the newsroom
    pub fn set_fpf_signature(&mut self, signature: Signature) {
        self.signature = Some(signature);
    }

    /// Get the ephemeral key count for a journalist
    pub fn ephemeral_keys_count(&self, journalist_id: Uuid) -> usize {
        self.storage.ephemeral_keys_count(journalist_id)
    }

    /// Check if a journalist has ephemeral keys available
    pub fn has_ephemeral_keys(&self, journalist_id: Uuid) -> bool {
        self.storage.has_ephemeral_keys(journalist_id)
    }

    /// Find journalist ID by verifying key
    pub fn find_journalist_id(&self, verifying_key: &VerifyingKey) -> Option<Uuid> {
        self.storage.find_journalist_by_verifying_key(verifying_key)
    }

    /// Check if a message exists with the given ID
    pub fn has_message(&self, message_id: &Uuid) -> bool {
        self.storage.get_messages().contains_key(message_id)
    }

    /// Handle source newsroom key request (step 5)
    pub fn handle_source_newsroom_key_request(
        &self,
        _request: SourceNewsroomKeyRequest,
    ) -> SourceNewsroomKeyResponse {
        SourceNewsroomKeyResponse {
            newsroom_verifying_key: self
                .newsroom_keys
                .as_ref()
                .expect("Newsroom keys not found")
                .vk,
            fpf_sig: self
                .signature
                .as_ref()
                .expect("FPF signature not found")
                .clone(),
        }
    }

    /// Handle source journalist key request (step 5)
    pub fn handle_source_journalist_key_request<R: RngCore + CryptoRng>(
        &mut self,
        _request: SourceJournalistKeyRequest,
        rng: &mut R,
    ) -> Vec<SourceJournalistKeyResponse> {
        let mut responses = Vec::new();

        // Get all journalists and their ephemeral keys
        let journalist_ephemeral_keys = self.storage.get_all_ephemeral_keys(rng);

        for (journalist_id, ephemeral_bundle) in journalist_ephemeral_keys {
            // Get the journalist's long-term keys
            // TODO: Do something better than expect here
            let (signing_key, fetching_key, newsroom_sig) = self
                .storage
                .get_journalists()
                .get(&journalist_id)
                .expect("Journalist should exist in storage")
                .clone();

            // Create response for this journalist
            // temp: duplicated the fetching key so things compile while we transition to 0.3 spec
            let response = SourceJournalistKeyResponse {
                journalist_sig_pk: signing_key,
                journalist_fetch_pk: fetching_key.clone(),
                journalist_dh_pk: fetching_key,
                newsroom_sig,
                one_time_message_pq_pk: ephemeral_bundle.public_keys.one_time_message_pq_pk,
                one_time_message_pk: ephemeral_bundle.public_keys.one_time_message_pk,
                one_time_metadata_pk: ephemeral_bundle.public_keys.one_time_metadata_pk,
                journalist_ephemeral_sig: ephemeral_bundle.signature,
            };

            responses.push(response);
        }

        responses
    }

    /// Handle message submission (step 6 for sources, step 9 for journalists)
    pub fn handle_message_submit(&mut self, message: Message) -> Result<Uuid, Error> {
        // Generate a random message ID
        let message_id = Uuid::new_v4();

        // Store the message with the generated ID
        self.storage.add_message(message_id, message);

        Ok(message_id)
    }

    /// Handle message ID fetch request (step 7)
    ///
    /// TODO: Nothing here prevents someone from requesting messages
    /// that aren't theirs? Should request messages have a signature?
    pub fn handle_message_id_fetch<R: RngCore + CryptoRng>(
        &self,
        _request: MessageChallengeFetchRequest,
        rng: &mut R,
    ) -> Result<MessageChallengeFetchResponse, Error> {
        let messages = self.storage.get_messages();
        let message_count = messages.len();

        // Fixed response size to prevent traffic analysis

        let mut q_entries = Vec::new();
        let mut cid_entries = Vec::new();

        // Process real messages
        for (message_id, message) in messages.iter() {
            let y = generate_random_scalar(rng).expect("Failed to generate random scalar");

            // k_i = DH(Z_i, y)
            let z_public_key = dh_public_key_from_scalar(
                message.dh_share_z.clone().try_into().unwrap_or([0u8; 32]),
            );
            let k_i = dh_shared_secret(&z_public_key, y)?.into_bytes();

            // Q_i = DH(X_i, y)
            let x_public_key = dh_public_key_from_scalar(
                message.dh_share_x.clone().try_into().unwrap_or([0u8; 32]),
            );
            let q_i = dh_shared_secret(&x_public_key, y)?.into_bytes();

            // ID: cid_i = Enc(k_i, id_i)
            let message_id_bytes = message_id.as_bytes().to_vec();
            let cid_i =
                encrypt_message_id(&k_i, &message_id_bytes).expect("Failed to encrypt message ID");

            q_entries.push(q_i.to_vec());
            cid_entries.push(cid_i);
        }

        // Fill remaining slots with random data
        while q_entries.len() < MESSAGE_ID_FETCH_SIZE {
            // Generate random Q_i that matches the structure of real Q_i
            // Real Q_i = DH(X_i, y), so random Q_i should also be a DH shared secret
            let random_y = generate_random_scalar(rng).expect("Failed to generate random scalar");
            let random_x = generate_random_scalar(rng).expect("Failed to generate random scalar");
            let random_x_pub = dh_public_key_from_scalar(random_x);
            let random_q = dh_shared_secret(&random_x_pub, random_y)
                .map_err(|_| anyhow!("failed to construct shared secret"))?
                .into_bytes();

            // Generate random cid by encrypting a random UUID
            // This ensures indistinguishability from real cid_i
            let random_uuid = Uuid::new_v4();
            let random_key = generate_random_scalar(rng).expect("Failed to generate random key");
            let random_cid =
                crate::primitives::encrypt_message_id(&random_key, random_uuid.as_bytes())
                    .expect("Failed to encrypt random UUID");

            q_entries.push(random_q.to_vec());
            cid_entries.push(random_cid);
        }

        // Shuffle the entries to hide which are real vs random
        // Zip the arrays together, shuffle, then unzip
        let mut pairs: Vec<_> = q_entries.into_iter().zip(cid_entries).collect();

        let shuffled = Self::shuffle_not_for_prod(&mut pairs)
            .expect("Need shuffled list")
            .to_vec();

        // Unzip back into separate arrays
        let (q_entries, cid_entries): (Vec<_>, Vec<_>) = shuffled.into_iter().unzip();

        Ok(MessageChallengeFetchResponse {
            count: MESSAGE_ID_FETCH_SIZE,
            messages: q_entries.into_iter().zip(cid_entries).collect(),
        })
    }

    /// Shuffle challenges so that real and decoys are interspersed.
    /// Note: not a true random shuffle, toybox impl only
    pub fn shuffle_not_for_prod<'a>(
        vec: &'a mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Option<&'a mut [(Vec<u8>, Vec<u8>)]> {
        if vec.is_empty() {
            return None;
        }

        let len = vec.len();

        // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
        for i in (0..len - 1).rev() {
            // not for prod: modulo bias
            let new_index = getrandom::u32().unwrap() as usize % i;
            vec.swap(i, new_index);
        }

        Some(vec.as_mut_slice())
    }

    /// Handle message fetch request (step 8/10)
    pub fn handle_message_fetch(
        &self,
        _request: MessageFetchRequest,
    ) -> Option<MessageFetchResponse> {
        unimplemented!()
    }

    /// Process a new refresh request from the journalist.
    ///
    /// TODO: The caller should persist the keys for J.
    ///
    /// Step 3.2 in the 0.2 spec.
    ///
    /// TODO(later): How to handle signing when offline? (Not relevant for benchmarking)
    pub fn handle_journalist_refresh(
        &mut self,
        _request: JournalistRefreshRequest,
    ) -> Result<(), Error> {
        // TODO: Check signature and store ephemeral keys
        unimplemented!()
    }
}
