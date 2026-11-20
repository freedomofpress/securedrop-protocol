//! Server-side protocol session
//!
//! This module holds the server state and implements the server-side handling
//! of the SecureDrop protocol steps, delegating the cryptographic operations
//! to `securedrop-protocol-minimal`.

use std::collections::HashMap;

use anyhow::{Error, anyhow};
use rand::{CryptoRng, Rng, RngExt};
use securedrop_protocol_minimal::challenge::MAX_MESSAGES;
use securedrop_protocol_minimal::keys::NewsroomKeyPair;
use securedrop_protocol_minimal::server::challenge::compute_fetch_challenges;
use securedrop_protocol_minimal::wire::core::{
    JournalistEphemeralKeys, JournalistLongTermView, MessageChallengeFetchRequest,
    MessageChallengeFetchResponse, MessageFetchRequest, WelcomeBundle,
};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistSetupRequest, JournalistSetupResponse,
    NewsroomSetupRequest,
};
use securedrop_protocol_minimal::{
    Enrollment, Envelope, FpfOnNewsroom, NewsroomOnJournalist, Signature, SignedKeyBundlePublic,
    VerifyingKey,
};
use uuid::Uuid;

/// Journalists are keyed by their long-term verifying key.
type JournalistId = [u8; VerifyingKey::LEN];

/// An enrolled journalist's long-term enrollment together with the newsroom's
/// signature over their verifying key, so it can be served to sources.
struct EnrolledJournalist {
    enrollment: Enrollment,
    nr_sig: Signature<NewsroomOnJournalist>,
}

/// Server session and in-memory storage.
///
/// Note: demo only, nothing is persisted to disk.
#[derive(Default)]
pub struct Server {
    newsroom_keys: Option<NewsroomKeyPair>,
    /// Signature from FPF over the newsroom keys
    signature: Option<Signature<FpfOnNewsroom>>,
    /// Enrolled journalists
    journalists: HashMap<JournalistId, EnrolledJournalist>,
    /// Journalists' ephemeral keystore: each journalist maintains a pool of
    /// ephemeral key bundles that are randomly selected and removed when fetched
    ephemeral_keys: HashMap<JournalistId, Vec<SignedKeyBundlePublic>>,
    /// Store of messages
    messages: HashMap<Uuid, Envelope>,
}

impl Server {
    /// Create a new server session without newsroom keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new server session from existing newsroom keys and
    /// (if available) the FPF signature over the newsroom verifying key.
    pub fn with_newsroom_keys(
        newsroom_keys: NewsroomKeyPair,
        signature: Option<Signature<FpfOnNewsroom>>,
    ) -> Self {
        Self {
            newsroom_keys: Some(newsroom_keys),
            signature,
            ..Self::default()
        }
    }

    /// Generate a new newsroom setup request.
    ///
    /// This creates a newsroom key pair, stores it in the session,
    /// and returns a setup request that can be sent to FPF for signing.
    pub fn create_newsroom_setup_request<R: Rng + CryptoRng>(
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

    /// Returns the newsroom verifying key, if one has been generated.
    pub fn newsroom_verifying_key(&self) -> Option<VerifyingKey> {
        self.newsroom_keys.as_ref().map(|keys| keys.verifying_key())
    }

    /// Set the FPF signature for the newsroom
    pub fn set_fpf_signature(&mut self, signature: Signature<FpfOnNewsroom>) {
        self.signature = Some(signature);
    }

    /// Setup a journalist. This corresponds to step 3.1 in the spec.
    ///
    /// The newsroom verifies and signs the journalist's enrollment, then
    /// stores it so the journalist can later replenish ephemeral keys and be
    /// served to sources.
    pub fn setup_journalist(
        &mut self,
        request: JournalistSetupRequest,
    ) -> Result<JournalistSetupResponse, Error> {
        let newsroom_keys = self
            .newsroom_keys
            .as_ref()
            .ok_or_else(|| anyhow!("Newsroom keys not found in session"))?;

        let response = request
            .sign(newsroom_keys)
            .map_err(|_| anyhow!("Invalid signature on longterm keys"))?;

        self.journalists.insert(
            request.enrollment.verification_key.into_bytes(),
            EnrolledJournalist {
                enrollment: request.enrollment,
                nr_sig: response.sig,
            },
        );

        Ok(response)
    }

    /// Handle journalist ephemeral key replenishment. This corresponds to step 3.2 in the spec.
    ///
    /// Returns the number of ephemeral key bundles now stored for this journalist.
    ///
    /// # Errors
    ///
    /// Returns an error if the journalist is not enrolled, or if any bundle
    /// signature fails verification.
    pub fn handle_ephemeral_key_request(
        &mut self,
        request: JournalistEphemeralKeyRequest,
    ) -> Result<usize, Error> {
        // Verify against the enrolled key from our own storage
        let vk_j = self
            .journalists
            .get(&request.verifying_key.into_bytes())
            .ok_or_else(|| anyhow!("Journalist not found in storage"))?
            .enrollment
            .verification_key;

        request
            .verify(&vk_j)
            .map_err(|_| anyhow!("Invalid signature on ephemeral keys"))?;

        let stored = self
            .ephemeral_keys
            .entry(request.verifying_key.into_bytes())
            .or_default();
        stored.extend(request.bundles);

        Ok(stored.len())
    }

    /// Check if a journalist with the given verifying key is enrolled
    pub fn is_enrolled(&self, verifying_key: &VerifyingKey) -> bool {
        self.journalists.contains_key(&verifying_key.into_bytes())
    }

    /// Get the ephemeral key count for a journalist
    pub fn ephemeral_keys_count(&self, verifying_key: &VerifyingKey) -> usize {
        self.ephemeral_keys
            .get(&verifying_key.into_bytes())
            .map_or(0, |keys| keys.len())
    }

    /// Check if a journalist has ephemeral keys available
    pub fn has_ephemeral_keys(&self, verifying_key: &VerifyingKey) -> bool {
        self.ephemeral_keys_count(verifying_key) > 0
    }

    /// Check if a message exists with the given ID
    pub fn has_message(&self, message_id: &Uuid) -> bool {
        self.messages.contains_key(message_id)
    }

    /// Serve the newsroom verifying key, the FPF signature over it, and the
    /// long-term keys of all enrolled journalists (step 5).
    ///
    /// # Errors
    ///
    /// Returns an error if the newsroom keys or FPF signature are not available.
    pub fn handle_welcome(&self) -> Result<WelcomeBundle, Error> {
        let newsroom_verifying_key = self
            .newsroom_verifying_key()
            .ok_or_else(|| anyhow!("Newsroom keys not found"))?;
        let fpf_sig = self
            .signature
            .ok_or_else(|| anyhow!("FPF signature not found"))?;

        let journalists = self
            .journalists
            .values()
            .map(|enrolled| JournalistLongTermView {
                vk: enrolled.enrollment.verification_key,
                signed_longterm_key_bundle: enrolled.enrollment.bundle.clone(),
                nr_signature: enrolled.nr_sig,
            })
            .collect();

        Ok(WelcomeBundle {
            newsroom_verifying_key,
            fpf_sig,
            journalists,
        })
    }

    /// Serve one random ephemeral key bundle per journalist (step 5).
    /// Only includes journalists that have available keys.
    ///
    /// Note: the returned bundles are permanently removed from each
    /// journalist's ephemeral key pool.
    pub fn handle_journalist_ephemeral_keys<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<JournalistEphemeralKeys> {
        let mut responses = Vec::new();

        for (journalist_id, enrolled) in self.journalists.iter() {
            let Some(bundles) = self
                .ephemeral_keys
                .get_mut(journalist_id)
                .filter(|b| !b.is_empty())
            else {
                continue;
            };
            let index = rng.random_range(0..bundles.len());

            responses.push(JournalistEphemeralKeys {
                vk: enrolled.enrollment.verification_key,
                ephemeral: bundles.swap_remove(index),
            });
        }

        responses
    }

    /// Handle message submission (step 6 for sources, step 9 for journalists)
    ///
    /// Stores the envelope under a freshly generated random message ID and
    /// returns the ID.
    pub fn handle_message_submit<R: Rng + CryptoRng>(
        &mut self,
        message: Envelope,
        rng: &mut R,
    ) -> Uuid {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        let message_id = uuid::Builder::from_random_bytes(bytes).into_uuid();

        self.messages.insert(message_id, message);

        message_id
    }

    /// Compute "hints"/challenges for message id fetch request (step 7)
    pub fn handle_request_challenges<R: Rng + CryptoRng>(
        &self,
        _request: MessageChallengeFetchRequest,
        rng: &mut R,
    ) -> MessageChallengeFetchResponse {
        let total_challenges: usize = MAX_MESSAGES;
        // Note that a real server would load these from a database rather than a
        // map in memory
        let entries: Vec<_> = self
            .messages
            .iter()
            .take(total_challenges)
            .map(|(uuid, envelope)| (*uuid.as_bytes(), envelope))
            .collect();
        let messages = compute_fetch_challenges(rng, &entries, total_challenges);

        MessageChallengeFetchResponse {
            count: total_challenges,
            messages,
        }
    }

    /// Handle message fetch request (step 8 and 10)
    pub fn handle_message_fetch(&self, request: MessageFetchRequest) -> Option<Envelope> {
        self.messages.get(&request.message_id).cloned()
    }
}
