use alloc::vec::Vec;
use hashbrown::HashMap;
use rand::{Rng, RngCore as RandRngCore};
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::keys::{JournalistEnrollmentKeyBundle, JournalistEphemeralKeyBundle};
use crate::messages::MessageBundle;
use crate::primitives::{DHPublicKey, MessageEncPublicKey};
use crate::sign::{Signature, VerifyingKey};

pub struct ServerStorage {
    /// Journalists with their long/medium term keys
    journalists: HashMap<Uuid, (VerifyingKey, DHPublicKey, DHPublicKey, Signature)>,
    /// Journalists ephemeral keystore
    /// Maps journalist ID to a vector of ephemeral key sets
    /// Each journalist maintains a pool of ephemeral keys that are randomly selected and removed when fetched
    ephemeral_keys: HashMap<Uuid, Vec<JournalistEphemeralKeyBundle>>,
    /// Store of messages
    messages: HashMap<Uuid, MessageBundle>,
}

impl ServerStorage {
    /// Create a new ServerStorage instance
    pub fn new() -> Self {
        Self {
            journalists: HashMap::new(),
            ephemeral_keys: HashMap::new(),
            messages: HashMap::new(),
        }
    }

    /// Add ephemeral keys for a journalist
    pub fn add_ephemeral_keys(
        &mut self,
        journalist_id: Uuid,
        keys: Vec<JournalistEphemeralKeyBundle>,
    ) {
        let journalist_keys = self
            .ephemeral_keys
            .entry(journalist_id)
            .or_insert_with(Vec::new);
        journalist_keys.extend(keys);
    }

    /// Get a random ephemeral key set for a journalist and remove it from the pool
    /// Returns None if no keys are available for this journalist
    ///
    /// Note: This method deletes the ephemeral key from storage.
    /// The returned key is permanently removed from the journalist's ephemeral key pool.
    pub fn pop_random_ephemeral_keys<R: rand::RngCore + CryptoRng>(
        &mut self,
        journalist_id: Uuid,
        rng: &mut R,
    ) -> Option<JournalistEphemeralKeyBundle> {
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
    ///
    /// Note: This method deletes the ephemeral keys from storage.
    /// Each call removes the returned keys from the journalist's ephemeral key pool.
    pub fn get_all_ephemeral_keys<R: rand::RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<(Uuid, JournalistEphemeralKeyBundle)> {
        let mut result = Vec::new();
        let journalist_ids: Vec<Uuid> = self.ephemeral_keys.keys().copied().collect();

        for journalist_id in journalist_ids {
            if let Some(keys) = self.pop_random_ephemeral_keys(journalist_id, rng) {
                result.push((journalist_id, keys));
            }
        }

        result
    }

    /// Check how many ephemeral keys are available for a journalist
    pub fn ephemeral_keys_count(&self, journalist_id: Uuid) -> usize {
        self.ephemeral_keys
            .get(&journalist_id)
            .map_or(0, |keys| keys.len())
    }

    /// Check if a journalist has any ephemeral keys available
    pub fn has_ephemeral_keys(&self, journalist_id: Uuid) -> bool {
        self.ephemeral_keys_count(journalist_id) > 0
    }

    /// Get all journalists
    pub fn get_journalists(
        &self,
    ) -> &HashMap<Uuid, (VerifyingKey, DHPublicKey, DHPublicKey, Signature)> {
        &self.journalists
    }

    /// Add a journalist to storage and return the generated UUID
    pub fn add_journalist(
        &mut self,
        enrollment_bundle: JournalistEnrollmentKeyBundle,
        signature: Signature,
    ) -> Uuid {
        let journalist_id = Uuid::new_v4();
        let keys = (
            enrollment_bundle.signing_key,
            enrollment_bundle.fetching_key,
            enrollment_bundle.dh_key,
            signature,
        );
        self.journalists.insert(journalist_id, keys);
        journalist_id
    }

    /// Find a journalist by their verifying key
    /// Returns the journalist ID if found
    ///
    /// TODO: Remove?
    pub fn find_journalist_by_verifying_key(&self, verifying_key: &VerifyingKey) -> Option<Uuid> {
        for (journalist_id, (stored_vk, _, _, _)) in &self.journalists {
            if stored_vk.into_bytes() == verifying_key.into_bytes() {
                return Some(*journalist_id);
            }
        }
        None
    }

    /// Get all messages
    pub fn get_messages(&self) -> &HashMap<Uuid, MessageBundle> {
        &self.messages
    }

    /// Add a message to storage
    pub fn add_message(&mut self, message_id: Uuid, message: MessageBundle) {
        self.messages.insert(message_id, message);
    }
}
