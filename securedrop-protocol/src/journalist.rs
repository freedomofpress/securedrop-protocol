//! Journalist-side protocol implementation
//!
//! This module implements the journalist-side handling of SecureDrop protocol steps 7-9.

use crate::messages::core::{MessageFetchResponse, MessageIdFetchResponse};
use crate::messages::setup::{JournalistSetupRequest, JournalistSetupResponse};
use crate::sign::SigningKey;
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

/// Journalist session for interacting with the server
pub struct JournalistSession {
    // TODO: Add journalist keys and state
}

impl JournalistSession {
    /// Create a new journalist session
    pub fn new() -> Self {
        Self {}
    }

    /// Generate a new journalist setup request.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn create_setup_request<R: RngCore + CryptoRng>(
        &self,
        mut rng: R,
    ) -> Result<JournalistSetupRequest, Error> {
        unimplemented!()
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
