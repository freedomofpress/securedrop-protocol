use alloc::vec::Vec;
use hashbrown::HashMap;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::messages::MessageBundle;
use crate::primitives::{DHPublicKey, PPKPublicKey};
use crate::sign::{Signature, VerifyingKey};

/// Ephemeral key set for a journalist
#[derive(Debug, Clone)]
pub struct JournalistEphemeralKeys {
    /// Ephemeral DH public key for DH-AKEM
    pub edh_pk: DHPublicKey,
    /// Ephemeral PPK public key for KEM
    pub ekem_pk: PPKPublicKey,
    /// Ephemeral PPK public key for PKE
    pub epke_pk: PPKPublicKey,
    /// Journalist's signature over the ephemeral keys
    pub signature: Signature,
}

pub struct ServerStorage {
    /// Newsroom verifying key
    newsroom_vk: VerifyingKey,
    /// Signature demonstrating onboarding
    fpf_sig: Signature,
    /// Journalists with their long term keys
    journalists: HashMap<u64, (VerifyingKey, DHPublicKey, DHPublicKey, Signature)>,
    /// Journalists ephemeral keystore
    /// Maps journalist ID to a vector of ephemeral key sets
    /// Each journalist maintains a pool of ephemeral keys that are randomly selected and removed when fetched
    ephemeral_keys: HashMap<u64, Vec<JournalistEphemeralKeys>>,
    /// Store of messages
    messages: HashMap<u64, MessageBundle>,
}

impl ServerStorage {
    /// Create a new ServerStorage instance
    pub fn new(newsroom_vk: VerifyingKey, fpf_sig: Signature) -> Self {
        Self {
            newsroom_vk,
            fpf_sig,
            journalists: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            messages: HashMap::new(),
        }
    }

    // TODO: Rename
    pub fn keys(self) -> (VerifyingKey, Signature) {
        (self.newsroom_vk, self.fpf_sig)
    }

    /// Add ephemeral keys for a journalist
    pub fn add_ephemeral_keys(&mut self, journalist_id: u64, keys: Vec<JournalistEphemeralKeys>) {
        let journalist_keys = self
            .ephemeral_keys
            .entry(journalist_id)
            .or_insert_with(Vec::new);
        journalist_keys.extend(keys);
    }

    /// Get a random ephemeral key set for a journalist and remove it from the pool
    /// Returns None if no keys are available for this journalist
    pub fn pop_random_ephemeral_keys<R: RngCore + CryptoRng>(
        &mut self,
        journalist_id: u64,
        rng: &mut R,
    ) -> Option<JournalistEphemeralKeys> {
        if let Some(keys) = self.ephemeral_keys.get_mut(&journalist_id) {
            if keys.is_empty() {
                return None;
            }

            // Select a random index
            let index = rng.gen_range(0..keys.len());

            // Remove and return the selected key set
            Some(keys.remove(index))
        } else {
            None
        }
    }

    /// Get random ephemeral keys for all journalists
    /// Returns a vector of (journalist_id, ephemeral_keys) pairs
    /// Only includes journalists that have available keys
    pub fn get_all_ephemeral_keys<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<(u64, JournalistEphemeralKeys)> {
        let mut result = Vec::new();
        let journalist_ids: Vec<u64> = self.ephemeral_keys.keys().copied().collect();

        for journalist_id in journalist_ids {
            if let Some(keys) = self.pop_random_ephemeral_keys(journalist_id, rng) {
                result.push((journalist_id, keys));
            }
        }

        result
    }

    /// Check how many ephemeral keys are available for a journalist
    pub fn ephemeral_keys_count(&self, journalist_id: u64) -> usize {
        self.ephemeral_keys
            .get(&journalist_id)
            .map_or(0, |keys| keys.len())
    }

    /// Check if a journalist has any ephemeral keys available
    pub fn has_ephemeral_keys(&self, journalist_id: u64) -> bool {
        self.ephemeral_keys_count(journalist_id) > 0
    }

    /// Get all journalists
    pub fn get_journalists(
        &self,
    ) -> &HashMap<u64, (VerifyingKey, DHPublicKey, DHPublicKey, Signature)> {
        &self.journalists
    }

    /// Add a journalist to storage
    pub fn add_journalist(
        &mut self,
        journalist_id: u64,
        keys: (VerifyingKey, DHPublicKey, DHPublicKey, Signature),
    ) {
        self.journalists.insert(journalist_id, keys);
    }

    /// Get all messages
    pub fn get_messages(&self) -> &HashMap<u64, MessageBundle> {
        &self.messages
    }

    /// Add a message to storage
    pub fn add_message(&mut self, message_id: u64, message: MessageBundle) {
        self.messages.insert(message_id, message);
    }

    /// Get the newsroom verifying key
    pub fn get_newsroom_vk(&self) -> &VerifyingKey {
        &self.newsroom_vk
    }

    /// Get the FPF signature
    pub fn get_fpf_sig(&self) -> &Signature {
        &self.fpf_sig
    }
}
