//! Server-side protocol implementation
//!
//! This module implements the server-side handling of SecureDrop protocol steps 5-10.

use alloc::vec::Vec;
use anyhow::{Error, anyhow};
use rand_core::{CryptoRng, RngCore};

use crate::keys::{
    JournalistDHKeyPair, JournalistEnrollmentKeyBundle, JournalistEphemeralKeyBundle,
    JournalistFetchKeyPair, JournalistSigningKeyPair, NewsroomKeyPair,
};
use crate::messages::core::{
    MessageFetchRequest, MessageFetchResponse, MessageIdFetchRequest, MessageIdFetchResponse,
    MessageSubmitRequest, SourceJournalistKeyRequest, SourceJournalistKeyResponse,
    SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
};
use crate::messages::setup::{
    JournalistRefreshRequest, JournalistSetupRequest, JournalistSetupResponse,
    NewsroomSetupRequest, NewsroomSetupResponse,
};
use crate::primitives::PPKPublicKey;
use crate::sign::Signature;
use crate::storage::ServerStorage;

/// Server session for handling source requests
pub struct ServerSession {
    storage: ServerStorage,
    newsroom_keys: Option<NewsroomKeyPair>,
    /// Signature from FPF over the newsroom keys
    signature: Option<Signature>,
}

impl ServerSession {
    /// Create a new server session
    ///
    /// TODO: Load newsroom keys from storage if they exist.
    pub fn new() -> Self {
        Self {
            storage: ServerStorage::new(),
            newsroom_keys: None,
            signature: None,
        }
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
        _rng: &mut R,
    ) -> Vec<SourceJournalistKeyResponse> {
        unimplemented!()
    }

    /// Handle message submission (step 6 for sources, step 9 for journalists)
    pub fn handle_message_submit<R: RngCore + CryptoRng>(
        &mut self,
        _request: MessageSubmitRequest,
        _rng: &mut R,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    /// Handle message ID fetch request (step 7)
    pub fn handle_message_id_fetch<R: RngCore + CryptoRng>(
        &self,
        _request: MessageIdFetchRequest,
        _rng: &mut R,
    ) -> MessageIdFetchResponse {
        unimplemented!()
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
