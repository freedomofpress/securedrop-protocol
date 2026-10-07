use alloc::vec::Vec;
use hashbrown::HashMap;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::keys::Epoch;
use crate::message::MessagePublicKey;
use crate::primitives::ristretto255::DHPublicKey;
use crate::sign::{JournalistLongTermKey, NewsroomOnJournalist, Signature, VerifyingKey};
use crate::{Enrollment, Envelope, SignedKeyBundlePublic, SignedLongtermKeyBundle};

pub type ServerMessageStore = HashMap<Uuid, Envelope>;

#[derive(Default)]
pub struct ServerStorage {
    /// Journalists with their long/medium term keys, self-signature, newsroom signature.
    journalists: HashMap<
        Uuid,
        (
            VerifyingKey,
            SignedLongtermKeyBundle,
            Signature<NewsroomOnJournalist>,
        ),
    >,

    /// Journalists short term keystore
    /// Maps journalist ID to a vector of short term key sets
    /// Each journalist maintains a pool of short term keys with a given validity window. They are removed when expired
    short_term_keys: HashMap<Uuid, Vec<SignedKeyBundlePublic>>,

    /// Store of messages
    messages: HashMap<Uuid, Envelope>,
}

impl ServerStorage {
    /// Create a new ServerStorage instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add short term keys for a journalist
    pub fn add_short_term_keys(&mut self, journalist_id: Uuid, keys: Vec<SignedKeyBundlePublic>) {
        let journalist_keys = self
            .short_term_keys
            .entry(journalist_id)
            // avoid `or_insert_with(Vec::new)` because hax doesn't accept FnMut/FnOnce closure
            .or_insert(Vec::new());
        journalist_keys.extend(keys);
    }

    /// Get a random short term key set valid in the `current` epoch for a journalist.
    /// Returns None if no keys are available for this journalist in `current`.
    ///
    /// Bundles are valid for their whole epoch and may be served any number of times,
    /// so the returned key stays in storage.
    ///
    /// Note: This method deletes any expired short term keys (epochs before `current`)
    /// for this journalist. Keys staged for later epochs are kept.
    pub fn random_short_term_keys<R: RngCore + CryptoRng>(
        &mut self,
        journalist_id: Uuid,
        rng: &mut R,
        current: Epoch,
    ) -> Option<SignedKeyBundlePublic> {
        let keys = self.short_term_keys.get_mut(&journalist_id)?;

        // Drop expired keys
        keys.retain(|key| key.epoch >= current);

        // Keys valid in the current epoch
        let candidates: Vec<&SignedKeyBundlePublic> =
            keys.iter().filter(|key| key.epoch == current).collect();
        if candidates.is_empty() {
            return None;
        }

        // Select a "random" index (note: Modulo bias, Toy purposes only!)
        let index = rng.next_u32() as usize % candidates.len();

        Some(candidates[index].clone())
    }

    /// Get a random short term key valid in the `current` epoch for each journalist
    /// Returns a vector of (journalist_id, short_term_key) pairs
    /// Only includes journalists that have available keys for `current`
    ///
    /// Note: Served keys stay in storage; expired keys are deleted.
    pub fn get_all_short_term_keys<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        current: Epoch,
    ) -> Vec<(Uuid, SignedKeyBundlePublic)> {
        let mut result = Vec::new();
        let journalist_ids: Vec<Uuid> = self.short_term_keys.keys().copied().collect();

        for journalist_id in journalist_ids {
            if let Some(keys) = self.random_short_term_keys(journalist_id, rng, current) {
                result.push((journalist_id, keys));
            }
        }

        result
    }

    /// Check how many short term keys are available for a journalist
    pub fn short_term_keys_count(&self, journalist_id: Uuid) -> usize {
        self.short_term_keys
            .get(&journalist_id)
            .map_or(0, |keys| keys.len())
    }

    /// Check if a journalist has any short term keys available
    pub fn has_short_term_keys(&self, journalist_id: Uuid) -> bool {
        self.short_term_keys_count(journalist_id) > 0
    }

    /// Get all journalists
    pub fn get_journalists(
        &self,
    ) -> &HashMap<
        Uuid,
        (
            VerifyingKey,
            SignedLongtermKeyBundle,
            Signature<NewsroomOnJournalist>,
        ),
    > {
        &self.journalists
    }

    /// Add a journalist to storage and return the generated UUID
    pub fn add_journalist(
        &mut self,
        journalist: Enrollment,
        newsroom_signature: Signature<NewsroomOnJournalist>,
    ) -> Uuid {
        let journalist_id = Uuid::new_v4();

        // match hashmap above
        let bundle = journalist.bundle;
        let values = (journalist.verification_key, bundle, newsroom_signature);

        self.journalists.insert(journalist_id, values);
        journalist_id
    }

    /// Find a journalist by their verifying key
    /// Returns the journalist ID if found
    ///
    /// TODO: Remove?
    pub fn find_journalist_by_verifying_key(&self, verifying_key: &VerifyingKey) -> Option<Uuid> {
        for (journalist_id, (stored_vk, _, _)) in &self.journalists {
            if stored_vk.into_bytes() == verifying_key.into_bytes() {
                return Some(*journalist_id);
            }
        }
        None
    }

    pub(crate) fn deterministic_uuid<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Uuid {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);

        uuid::Builder::from_random_bytes(bytes).into_uuid()
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
