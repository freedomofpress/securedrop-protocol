//! Server-side protocol implementation
//!
//! This module implements the server-side handling of SecureDrop protocol steps 5-10.

use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

use crate::{Envelope, SignedKeyBundlePublic};
use crate::encrypt_decrypt::compute_fetch_challenges;
use crate::keys::{Epoch, NewsroomKeyPair, Timestamp};
use crate::primitives;
use crate::sign::{FpfOnNewsroom, NewsroomOnJournalist, Signature, VerifyingKey};
use crate::storage::ServerStorage;
use crate::wire::core::{
    JournalistLongTermView, JournalistShortTermKeys, MessageChallengeFetchRequest,
    MessageChallengeFetchResponse, MessageFetchRequest, WelcomeBundle,
};
use crate::wire::setup::{
    JournalistSetupRequest, JournalistSetupResponse, JournalistShortTermKeyRequest,
    NewsroomSetupRequest,
};


/// Server policy for short-term key bundles.
#[derive(Debug, Clone, Copy)]
pub struct ShortTermKeyPolicy {
    /// Number of future epochs a journalist can stage bundles for (`REPLENISHMENT`)
    pub replenishment: u64,
    /// Allowed clock difference between the server and journalists, in seconds
    /// (`SKEW`)
    pub skew: u64,
}

impl Default for ShortTermKeyPolicy {
    fn default() -> Self {
        Self {
            replenishment: 7,
            skew: 5 * 60,
        }
    }
}

impl ShortTermKeyPolicy {
    /// The epoch at `now`
    pub fn current_epoch(&self, now: Timestamp) -> Epoch {
        Epoch::containing(now)
    }

    /// Range of bundle epochs the server accepts at `now`. This is the current epoch plus `replenishment` epochs, and allowing for a `skew` in the journalist's clock.
    pub fn acceptable_upload_epochs(&self, now: Timestamp) -> (Epoch, Epoch) {
        let first = Epoch::containing(now);
        let ahead = Epoch::containing(Timestamp(now.0.saturating_add(self.skew)));
        (first, Epoch(ahead.0.saturating_add(self.replenishment)))
    }
}


/// Server session for handling source requests
#[derive(Default)]
pub struct Server {
    storage: ServerStorage,
    newsroom_keys: Option<NewsroomKeyPair>,
    /// Signature from FPF over the newsroom keys
    signature: Option<Signature<FpfOnNewsroom>>,
    /// Policy for short-term key bundles
    short_term_policy: ShortTermKeyPolicy,
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
        rng: &mut R,
    ) -> Result<NewsroomSetupRequest, Error> {
        let newsroom_keys = NewsroomKeyPair::new(rng)?;
        let newsroom_vk = newsroom_keys.verifying_key();

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
        // Get enrollment key from the request
        let journalist_signing_key = request.enrollment.verification_key;

        // Verify journalist self-signature over their own pubkeys.
        journalist_signing_key
            .verify(
                &request.enrollment.bundle.bundle_bytes(),
                &request.enrollment.bundle.selfsig,
            )
            .map_err(|_| anyhow::anyhow!("Invalid signature on longterm keys"))?;

        // Sign the journalist's verifying key.
        let verifying_key_bytes = request.enrollment.verification_key.into_bytes();
        let newsroom_keys = self
            .newsroom_keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Newsroom keys not found in session"))?;
        let newsroom_signature: Signature<NewsroomOnJournalist> =
            newsroom_keys.sign(&verifying_key_bytes);

        // Insert journalist keys into storage
        let _journalist_id = self
            .storage
            .add_journalist(request.enrollment, newsroom_signature.clone());

        Ok(JournalistSetupResponse {
            sig: newsroom_signature,
        })
    }

    /// Handle journalist short term key replenishment. This corresponds to step 3.2 in the spec.
    ///
    /// The journalist sends short term keys signed by their signing key, and the server
    /// verifies the signature and stores the short term keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the journalist is not found in storage, a bundle signature fails verification, or a bundle validity window is not in range.
    pub fn handle_short_term_key_request(
        &mut self,
        request: JournalistShortTermKeyRequest,
        now: Timestamp,
    ) -> Result<(), Error> {
        // Look up the journalist by their verifying key
        let journalist_id = self
            .storage
            .find_journalist_by_verifying_key(&request.verifying_key)
            .ok_or_else(|| anyhow::anyhow!("Journalist not found in storage"))?;

        // TODO: more efficient way than verifying each signature!
        // Verify each short term bundle signature.
        request
            .bundles
            .iter()
            .try_for_each(|k| request.verifying_key.verify(&k.signed_bytes(), &k.selfsig))
            .map_err(|_| anyhow::anyhow!("Invalid signature on short term keys"))?;

        // Check bundle validity
        let (first, last) = self.short_term_policy.acceptable_upload_epochs(now);
        let valid_bundles: Vec<SignedKeyBundlePublic> = request
            .bundles
            .into_iter()
            .filter(|k| k.epoch >= first && k.epoch <= last)
            .collect();

        // Store the short term keys for the journalist
        self.storage
            .add_short_term_keys(journalist_id, valid_bundles);

        Ok(())
    }

    /// Returns the newsroom verifying key, if one has been generated.
    pub fn newsroom_verifying_key(&self) -> Option<VerifyingKey> {
        self.newsroom_keys.as_ref().map(|keys| keys.verifying_key())
    }

    /// Set the FPF signature for the newsroom
    pub fn set_fpf_signature(&mut self, signature: Signature<FpfOnNewsroom>) {
        self.signature = Some(signature);
    }

    /// Get the short term key count for a journalist
    pub fn short_term_keys_count(&self, journalist_id: Uuid) -> usize {
        self.storage.short_term_keys_count(journalist_id)
    }

    /// Check if a journalist has short term keys available
    pub fn has_short_term_keys(&self, journalist_id: Uuid) -> bool {
        self.storage.has_short_term_keys(journalist_id)
    }

    /// Find journalist ID by verifying key
    pub fn find_journalist_id(&self, verifying_key: &VerifyingKey) -> Option<Uuid> {
        self.storage.find_journalist_by_verifying_key(verifying_key)
    }

    /// Check if a message exists with the given ID
    pub fn has_message(&self, message_id: &Uuid) -> bool {
        self.storage.get_messages().contains_key(message_id)
    }

    pub fn handle_welcome(&self) -> WelcomeBundle {
        let newsroom_verifying_key = self
            .newsroom_keys
            .as_ref()
            .expect("Newsroom keys not found")
            .verifying_key();
        let fpf_sig = self
            .signature
            .as_ref()
            .expect("FPF signature not found")
            .clone();

        let mut journalists = Vec::new();
        for (_id, entry) in self.storage.get_journalists().iter() {
            let (vk, signed_longterm_key_bundle, nr_signature) = entry.clone();
            journalists.push(JournalistLongTermView {
                vk,
                signed_longterm_key_bundle,
                nr_signature,
            });
        }

        WelcomeBundle {
            newsroom_verifying_key,
            fpf_sig,
            journalists,
        }
    }

    pub fn handle_journalist_short_term_keys<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        now: Timestamp,
    ) -> Vec<JournalistShortTermKeys> {
        let current = self.short_term_policy.current_epoch(now);

        let mut responses = Vec::new();

        let journalist_short_term_keys = self.storage.get_all_short_term_keys(rng, current);

        for (journalist_id, short_term_bundle) in journalist_short_term_keys.iter() {
            // TODO: Do something better than expect here
            let entry = self
                .storage
                .get_journalists()
                .get(journalist_id)
                .expect("Journalist should exist in storage")
                .clone();
            let vk = entry.0;

            responses.push(JournalistShortTermKeys {
                vk,
                short_term: short_term_bundle.clone(),
            });
        }

        responses
    }

    /// Handle message submission (step 6 for sources, step 9 for journalists)
    pub fn handle_message_submit<R: RngCore + CryptoRng>(
        &mut self,
        message: Envelope,
        rng: &mut R,
    ) -> Result<Uuid, Error> {
        // Generate a random message ID
        let message_id = self.storage.deterministic_uuid(rng);

        // Store the message with the generated ID
        self.storage.add_message(message_id, message);

        Ok(message_id)
    }

    /// Compute "hints"/challenges for message id fetch request (step 7)
    pub fn handle_request_challenges<R: RngCore + CryptoRng>(
        &self,
        _request: MessageChallengeFetchRequest,
        rng: &mut R,
    ) -> Result<MessageChallengeFetchResponse, Error> {
        let total_challenges: usize = primitives::MESSAGE_ID_FETCH_SIZE;
        let entries: Vec<_> = self
            .storage
            .get_messages()
            .iter()
            .take(total_challenges)
            .map(|(uuid, envelope)| (*uuid.as_bytes(), envelope.clone()))
            .collect();
        let chall = compute_fetch_challenges(rng, &entries, total_challenges);

        Ok(MessageChallengeFetchResponse {
            count: total_challenges,
            messages: chall,
        })
    }

    /// Handle message ID fetch request (step 7)
    ///
    /// TODO: Nothing here prevents someone from requesting messages
    /// that aren't theirs? Should request messages have a signature?
    // #[deprecated] // "use compute_fetch_challenges"
    // pub fn handle_message_id_fetch<R: RngCore + CryptoRng>(
    //     &self,
    //     _request: MessageChallengeFetchRequest,
    //     rng: &mut R,
    // ) -> Result<MessageChallengeFetchResponse, Error> {
    //     let messages = self.storage.get_messages();
    //     let message_count = messages.len();
    //     // Fixed response size to prevent traffic analysis

    //     let mut q_entries = Vec::new();
    //     let mut cid_entries = Vec::new();

    //     // Process real messages
    //     for (message_id, message) in messages.iter() {
    //         let y = generate_random_scalar(rng).expect("Failed to generate random scalar");

    //         // k_i = DH(Z_i, y)
    //         let z_public_key = dh_public_key_from_scalar(
    //             message.dh_share_z.clone().try_into().unwrap_or([0u8; 32]),
    //         );
    //         let k_i = dh_shared_secret(&z_public_key, y)?.into_bytes();

    //         // Q_i = DH(X_i, y)
    //         let x_public_key = dh_public_key_from_scalar(
    //             message.dh_share_x.clone().try_into().unwrap_or([0u8; 32]),
    //         );
    //         let q_i = dh_shared_secret(&x_public_key, y)?.into_bytes();

    //         // ID: cid_i = Enc(k_i, id_i)
    //         let message_id_bytes = message_id.as_bytes().to_vec();
    //         let cid_i =
    //             encrypt_message_id(&k_i, &message_id_bytes).expect("Failed to encrypt message ID");

    //         q_entries.push(q_i.to_vec());
    //         cid_entries.push(cid_i);
    //     }

    //     // Fill remaining slots with random data
    //     while q_entries.len() < MESSAGE_ID_FETCH_SIZE {
    //         // Generate random Q_i that matches the structure of real Q_i
    //         // Real Q_i = DH(X_i, y), so random Q_i should also be a DH shared secret
    //         let random_y = generate_random_scalar(rng).expect("Failed to generate random scalar");
    //         let random_x = generate_random_scalar(rng).expect("Failed to generate random scalar");
    //         let random_x_pub = dh_public_key_from_scalar(random_x);
    //         let random_q = dh_shared_secret(&random_x_pub, random_y)
    //             .map_err(|_| anyhow!("failed to construct shared secret"))?
    //             .into_bytes();

    //         // Generate random cid by encrypting a random UUID
    //         // This ensures indistinguishability from real cid_i
    //         let random_uuid = Uuid::new_v4();
    //         let random_key = generate_random_scalar(rng).expect("Failed to generate random key");
    //         let random_cid =
    //             crate::primitives::encrypt_message_id(&random_key, random_uuid.as_bytes())
    //                 .expect("Failed to encrypt random UUID");

    //         q_entries.push(random_q.to_vec());
    //         cid_entries.push(random_cid);
    //     }

    //     // Shuffle the entries to hide which are real vs random
    //     // Zip the arrays together, shuffle, then unzip
    //     let mut pairs: Vec<_> = q_entries.into_iter().zip(cid_entries).collect();

    //     let shuffled = Self::shuffle_not_for_prod(&mut pairs)
    //         .expect("Need shuffled list")
    //         .to_vec();

    //     // Unzip back into separate arrays
    //     let (q_entries, cid_entries): (Vec<_>, Vec<_>) = shuffled.into_iter().unzip();

    //     Ok(MessageChallengeFetchResponse {
    //         count: MESSAGE_ID_FETCH_SIZE,
    //         messages: q_entries.into_iter().zip(cid_entries).collect(),
    //     })
    // }

    // /// Shuffle challenges so that real and decoys are interspersed.
    // /// Note: not a true random shuffle, toybox impl only
    // pub fn shuffle_not_for_prod<'a>(
    //     vec: &'a mut Vec<(Vec<u8>, Vec<u8>)>,
    // ) -> Option<&'a mut [(Vec<u8>, Vec<u8>)]> {
    //     if vec.is_empty() {
    //         return None;
    //     }

    //     let len = vec.len();

    //     // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
    //     for i in (0..len - 1).rev() {
    //         // not for prod: modulo bias
    //         let new_index = getrandom::u32().unwrap() as usize % i;
    //         vec.swap(i, new_index);
    //     }

    //     Some(vec.as_mut_slice())
    // }

    /// Handle message fetch request (step 8/10)
    pub fn handle_message_fetch(&self, request: MessageFetchRequest) -> Option<Envelope> {
        self.storage
            .get_messages()
            .get(&request.message_id)
            .cloned()
    }
}
