//! Source-side protocol implementation
//!
//! This module implements the source-side handling of SecureDrop protocol steps 5-10.

use crate::keys::{SourceKeyBundle, SourcePassphrase};
use crate::messages::core::{
    MessageFetchResponse, MessageIdFetchResponse, SourceJournalistKeyResponse,
    SourceNewsroomKeyResponse,
};
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
