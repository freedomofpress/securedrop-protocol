//! Source-side protocol implementation
//!
//! This module implements the source-side handling of SecureDrop protocol steps 5-10.

use crate::messages::core::{
    MessageFetchResponse, MessageIdFetchResponse, SourceJournalistKeyResponse,
    SourceNewsroomKeyResponse,
};
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

/// Source session for interacting with the server
pub struct SourceSession {
    // TODO: Add source keys and state
}

impl SourceSession {
    /// Create a new source session
    pub fn new() -> Self {
        Self {}
    }

    /// Fetch newsroom keys (step 5)
    pub fn fetch_newsroom_keys(&self) -> SourceNewsroomKeyResponse {
        unimplemented!()
    }

    /// Fetch journalist keys (step 5)
    pub fn fetch_journalist_keys<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> Vec<SourceJournalistKeyResponse> {
        unimplemented!()
    }

    /// Submit a message (step 6)
    pub fn submit_message<R: RngCore + CryptoRng>(
        &self,
        _message: Vec<u8>,
        _rng: &mut R,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    /// Fetch message IDs (step 7)
    pub fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
    ) -> MessageIdFetchResponse {
        unimplemented!()
    }

    /// Fetch a specific message (step 10)
    pub fn fetch_message(&self, _message_id: u64) -> Option<MessageFetchResponse> {
        unimplemented!()
    }
}
