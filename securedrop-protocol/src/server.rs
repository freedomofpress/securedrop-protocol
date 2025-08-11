//! Server-side protocol implementation
//!
//! This module implements the server-side handling of SecureDrop protocol steps 5-10.

use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

use crate::messages::core::{
    MessageFetchRequest, MessageFetchResponse, MessageIdFetchRequest, MessageIdFetchResponse,
    MessageSubmitRequest, SourceJournalistKeyRequest, SourceJournalistKeyResponse,
    SourceNewsroomKeyRequest, SourceNewsroomKeyResponse,
};
use crate::messages::setup::{JournalistRefreshRequest, JournalistSetupResponse};
use crate::storage::{JournalistEphemeralKeys, ServerStorage};

/// Server session for handling source requests
pub struct ServerSession {
    storage: ServerStorage,
}

impl ServerSession {
    /// Create a new server session
    pub fn new(storage: ServerStorage) -> Self {
        Self { storage }
    }

    /// Setup a journalist. This corresponds to step 3.1 in the spec.
    ///
    /// The generated journalist keys are sent to the newsroom,
    /// which produces a signature over the bundle of journalist keys using
    /// the newsroom signing key.
    ///
    /// TODO: There is a manual verification step here, so the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    pub fn setup_journalist(&self) -> Result<JournalistSetupResponse, Error> {
        unimplemented!()
    }

    /// Handle source newsroom key request (step 5)
    pub fn handle_source_newsroom_key_request(
        &self,
        _request: SourceNewsroomKeyRequest,
    ) -> SourceNewsroomKeyResponse {
        SourceNewsroomKeyResponse {
            newsroom_verifying_key: self.storage.get_newsroom_vk().clone(),
            fpf_sig: self.storage.get_fpf_sig().clone(),
        }
    }

    /// Handle source journalist key request (step 5)
    pub fn handle_source_journalist_key_request<R: RngCore + CryptoRng>(
        &mut self,
        _request: SourceJournalistKeyRequest,
        rng: &mut R,
    ) -> Vec<SourceJournalistKeyResponse> {
        unimplemented!()
    }

    /// Handle message submission (step 6 for sources, step 9 for journalists)
    pub fn handle_message_submit<R: RngCore + CryptoRng>(
        &mut self,
        request: MessageSubmitRequest,
        rng: &mut R,
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
    pub fn handle_journalist_refresh(
        &mut self,
        _request: JournalistRefreshRequest,
    ) -> Result<(), Error> {
        // TODO: Check signature and store ephemeral keys
        unimplemented!()
    }
}
