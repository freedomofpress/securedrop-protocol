use alloc::vec::Vec;
use getrandom;
use hashbrown::HashMap;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::x25519::DHPublicKey;
use crate::sign::{SelfSignature, Signature, VerifyingKey};
use crate::types::{Enrollment, Envelope, SignedKeyBundlePublic, SignedLongtermPubKeyBytes};

pub type ServerMessageStore = HashMap<Uuid, Envelope>;

#[derive(Default)]
pub struct ServerStorage {
    /// Journalists with their long/medium term keys, self-signature, newsroom signature.
    journalists: HashMap<
        Uuid,
        (
            VerifyingKey,
            DHPublicKey,
            DhAkemPublicKey,
            SelfSignature,
            SignedLongtermPubKeyBytes,
            Signature,
        ),
    >,

    /// Journalists ephemeral keystore
    /// Maps journalist ID to a vector of ephemeral key sets
    /// Each journalist maintains a pool of ephemeral keys that are randomly selected and removed when fetched
    /// TODO recheck lifetime
    ephemeral_keys: HashMap<Uuid, Vec<SignedKeyBundlePublic>>,

    /// Store of messages
    messages: HashMap<Uuid, Envelope>,
}

impl ServerStorage {
    /// Create a new ServerStorage instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add ephemeral keys for a journalist
    pub fn add_ephemeral_keys(&mut self, journalist_id: Uuid, keys: Vec<SignedKeyBundlePublic>) {
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
    pub fn pop_random_ephemeral_keys<R: RngCore + CryptoRng>(
        &mut self,
        journalist_id: Uuid,
        rng: &mut R,
    ) -> Option<SignedKeyBundlePublic> {
        if let Some(keys) = self.ephemeral_keys.get_mut(&journalist_id) {
            if keys.is_empty() {
                return None;
            }

            // Select a "random" index (note: Modulo bias, Toy purposes only!)
            let index = getrandom::u32().unwrap() as usize % keys.len();

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
    pub fn get_all_ephemeral_keys<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<(Uuid, SignedKeyBundlePublic)> {
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
    ) -> &HashMap<
        Uuid,
        (
            VerifyingKey,
            DHPublicKey,
            DhAkemPublicKey,
            SelfSignature,
            SignedLongtermPubKeyBytes,
            Signature,
        ),
    > {
        &self.journalists
    }

    /// Add a journalist to storage and return the generated UUID
    pub fn add_journalist(
        &mut self,
        journalist: Enrollment,
        newsroom_signature: Signature,
    ) -> Uuid {
        let journalist_id = Uuid::new_v4();
        // match hashmap above
        let values = (
            journalist.keys.0,
            journalist.keys.1,
            journalist.keys.2,
            journalist.selfsig,
            journalist.bundle,
            newsroom_signature,
        );

        self.journalists.insert(journalist_id, values);
        journalist_id
    }

    /// Find a journalist by their verifying key
    /// Returns the journalist ID if found
    ///
    /// TODO: Remove?
    pub fn find_journalist_by_verifying_key(&self, verifying_key: &VerifyingKey) -> Option<Uuid> {
        for (journalist_id, (stored_vk, _, _, _, _, _)) in &self.journalists {
            if stored_vk.into_bytes() == verifying_key.into_bytes() {
                return Some(*journalist_id);
            }
        }
        None
    }

    /// Get all messages
    pub fn get_messages(&self) -> &HashMap<Uuid, Envelope> {
        &self.messages
    }

    /// Add a message to storage
    pub fn add_message(&mut self, message_id: Uuid, message: Envelope) {
        self.messages.insert(message_id, message);
    }
}
