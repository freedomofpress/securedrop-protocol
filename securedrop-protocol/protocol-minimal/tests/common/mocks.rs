//! Server-side protocol implementation
//!
//! This module implements the server-side handling of SecureDrop protocol steps 5-10.

use anyhow::{Error, anyhow};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

// used to cheat a bit with connecting the mock app (stateless api, &self)
// to the mock server (stateful, &mut self)
use std::cell::RefCell;

use securedrop_protocol_minimal::Envelope;
use securedrop_protocol_minimal::api::{
    ClientApplicationData, HasRng, JournalistApplicationContract, ServerApiError, ServerContract,
};
use securedrop_protocol_minimal::keys::NewsroomKeyPair;
use securedrop_protocol_minimal::schemes::challenge::MAX_MESSAGES;
use securedrop_protocol_minimal::server::challenge::compute_fetch_challenges;
use securedrop_protocol_minimal::sign::{
    FpfOnNewsroom, NewsroomOnJournalist, Signature, VerifyingKey,
};
use securedrop_protocol_minimal::wire::core::{
    JournalistEphemeralKeys, JournalistLongTermView, MessageChallengeFetchRequest,
    MessageChallengeFetchResponse, MessageFetchRequest, WelcomeBundle, WelcomeBundleRequest,
};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistEphemeralKeyResponse, JournalistSetupRequest,
    JournalistSetupResponse, NewsroomSetupRequest,
};

/// Server session for handling source requests
pub(crate) struct Server {
    pub(crate) storage: ServerStorage,
    newsroom_keys: Option<NewsroomKeyPair>,
    /// Signature from FPF over the newsroom keys
    signature: Option<Signature<FpfOnNewsroom>>,
    rng: ChaCha20Rng,
}

impl Server {
    pub(crate) fn new(
        storage: ServerStorage,
        newsroom_keys: Option<NewsroomKeyPair>,
        signature: Option<Signature<FpfOnNewsroom>>,
        rng: ChaCha20Rng,
    ) -> Self {
        Self {
            storage,
            newsroom_keys,
            signature,
            rng,
        }
    }

    /// Generate a new newsroom setup request.
    ///
    /// This creates a newsroom key pair, stores it in the server storage,
    /// and returns a setup request that can be sent to FPF for signing.
    ///
    /// TODO: The caller should persist these keys to disk.
    pub fn create_newsroom_setup_request(&mut self) -> Result<NewsroomSetupRequest, Error> {
        let newsroom_keys = NewsroomKeyPair::new(&mut self.rng)?;
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

    /// Handle journalist ephemeral key replenishment. This corresponds to step 3.2 in the spec.
    ///
    /// The journalist sends ephemeral keys signed by their signing key, and the server
    /// verifies the signature and stores the ephemeral keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the journalist is not found in storage, or if any bundle
    /// signature fails verification.
    /// Otherwise return the number of ephemeral keys available for that journalist.
    pub fn handle_ephemeral_key_request(
        &mut self,
        request: JournalistEphemeralKeyRequest,
    ) -> Result<JournalistEphemeralKeyResponse, Error> {
        // Look up the journalist by their verifying key
        let journalist_id = self
            .storage
            .find_journalist_by_verifying_key(&request.verifying_key)
            .ok_or_else(|| anyhow::anyhow!("Journalist not found in storage"))?;

        // TODO: more efficient way than verifying each signature!
        // Verify each ephemeral bundle signature.
        request
            .bundles
            .iter()
            .try_for_each(|k| request.verifying_key.verify(&k.0.as_bytes(), &k.1))
            .map_err(|_| anyhow::anyhow!("Invalid signature on ephemeral keys"))?;

        // Store the ephemeral keys for the journalist
        self.storage
            .add_ephemeral_keys(journalist_id, request.bundles);

        Ok(JournalistEphemeralKeyResponse {
            stored: self.ephemeral_keys_count(journalist_id),
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

    /// Get the ephemeral key count for a journalist
    pub fn ephemeral_keys_count(&self, journalist_id: Uuid) -> usize {
        self.storage.ephemeral_keys_count(journalist_id)
    }

    /// Check if a journalist has ephemeral keys available
    pub fn has_ephemeral_keys(&self, journalist_id: Uuid) -> bool {
        self.storage.has_ephemeral_keys(journalist_id)
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

    pub fn handle_journalist_ephemeral_keys<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Vec<JournalistEphemeralKeys> {
        let mut responses = Vec::new();

        let journalist_ephemeral_keys = self.storage.get_all_ephemeral_keys(rng);

        for (journalist_id, ephemeral_bundle) in journalist_ephemeral_keys.iter() {
            // TODO: Do something better than expect here
            let entry = self
                .storage
                .get_journalists()
                .get(journalist_id)
                .expect("Journalist should exist in storage")
                .clone();
            let vk = entry.0;

            responses.push(JournalistEphemeralKeys {
                vk,
                ephemeral: ephemeral_bundle.clone(),
            });
        }

        responses
    }

    /// Handle message submission (step 6 for sources, step 9 for journalists)
    pub fn handle_message_submit(&mut self, message: Envelope) -> Result<Uuid, Error> {
        // Generate a random message ID
        let mut rng = self.rng.clone();
        let message_id = self.storage.deterministic_uuid(&mut rng);

        // Store the message with the generated ID
        self.storage.add_message(message_id, message);

        Ok(message_id)
    }

    /// Compute "hints"/challenges for message id fetch request (step 7)
    pub fn handle_request_challenges(
        &mut self,
        _request: MessageChallengeFetchRequest,
    ) -> Result<MessageChallengeFetchResponse, Error> {
        let total_challenges: usize = MAX_MESSAGES;
        let entries: Vec<_> = self
            .storage
            .get_messages()
            .iter()
            .take(total_challenges)
            .map(|(uuid, envelope)| (*uuid.as_bytes(), envelope.clone()))
            .collect();
        let mut lrng = self.rng().clone();
        let chall = compute_fetch_challenges(&mut lrng, &entries, total_challenges);

        Ok(MessageChallengeFetchResponse {
            count: total_challenges,
            messages: chall,
        })
    }

    /// Handle message fetch request (step 8/10)
    pub fn handle_message_fetch(&self, request: MessageFetchRequest) -> Option<Envelope> {
        self.storage
            .get_messages()
            .get(&request.message_id)
            .cloned()
    }
}

use hashbrown::HashMap;

use securedrop_protocol_minimal::message::MessagePublicKey;
use securedrop_protocol_minimal::sign::JournalistLongTermKey;
use securedrop_protocol_minimal::{Enrollment, SignedKeyBundlePublic, SignedLongtermKeyBundle};

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
            // avoid `or_insert_with(Vec::new)` because hax doesn't accept FnMut/FnOnce closure
            .or_insert(Vec::new());
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
            let index = rng.next_u32() as usize % keys.len();

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

//// messy but on the way to migrating the server to be generically behind the server contract abstraction.
/// the goal is to refactor all the calls to server methods to be behind this abstraction, then restrict their visibility.
/// the demo server and test server impl should use the same trait to ensure they fulfill the same requirements.

impl HasRng for Server {
    type Rng = ChaCha20Rng;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }
}

impl ServerContract for Server {
    fn verifying_key(&self) -> Result<VerifyingKey, ServerApiError> {
        self.newsroom_verifying_key().ok_or(anyhow!("need nr key "))
    }

    fn welcome(&self, req: WelcomeBundleRequest) -> Result<WelcomeBundle, ServerApiError> {
        Ok(self.handle_welcome())
    }

    fn challenges(
        &mut self,
        req: MessageChallengeFetchRequest,
    ) -> Result<MessageChallengeFetchResponse, ServerApiError> {
        self.handle_request_challenges(req)
    }

    fn message_get(&self, req: MessageFetchRequest) -> Result<Option<Envelope>, ServerApiError> {
        Ok(self.handle_message_fetch(req))
    }

    fn message_submit(&mut self, ct: Envelope) -> Result<(), ServerApiError> {
        self.handle_message_submit(ct);
        Ok(())
    }

    fn journalist_enroll(
        &mut self,
        req: JournalistSetupRequest,
    ) -> Result<JournalistSetupResponse, ServerApiError> {
        self.setup_journalist(req)
    }

    fn journalist_short_lived_keys(
        &mut self,
        req: JournalistEphemeralKeyRequest,
    ) -> Result<
        securedrop_protocol_minimal::wire::setup::JournalistEphemeralKeyResponse,
        ServerApiError,
    > {
        let stored = self.handle_ephemeral_key_request(req)?;
        Ok(stored)
    }
}

use securedrop_protocol_minimal::api::{
    Api, ApplicationCallback, ApplicationContract, DefaultProtocol, JournalistApi, NetworkError,
};

// Mock application core that can be used for integration testing. It invokes the DefaultProtocol
// implementation and a (pretend) network application.
// Note that the application works with both source and journalist, and does not bind a user's
// keys to the context or include any storge. User-specific impl goes in source-cli or journalist-cli.
//
// A real application wouldn't own a reference to the server, it would just implement the
// network API. For testing purposes we make an app that immediately forwards results to a
// mock server and returns the results, simulating networking.
// the RefCell is a bit of cheating - the API is stateless (&self) but the Server is stateful
// (&mut self) and for test purposes we make it work.
pub(crate) struct MockApp<'a>(VerifyingKey, ChaCha20Rng, RefCell<&'a mut Server>);

// The mock app has the lifetime of the mockserver for test purposes
impl MockApp<'_> {
    pub(crate) fn new(vk: VerifyingKey, c: ChaCha20Rng, s: &mut Server) -> MockApp<'_> {
        MockApp(vk, c, RefCell::new(s))
    }
}

impl HasRng for MockApp<'_> {
    type Rng = ChaCha20Rng;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.1
    }
}

pub struct StubGuiCallback;
impl ApplicationCallback for StubGuiCallback {
    // Ignore gui callbacks for testing
    fn on_result<T>(data: ClientApplicationData<T>) {}
}

// This is the entire application that downstream crates implement.
// Provide a network API implementation, a GUI callbacks implementation, and rely on the
// DefaultProtocol implementation.
impl ApplicationContract for MockApp<'_> {
    type NetworkApi = Self;

    type Protocol = DefaultProtocol;

    // Ignore gui callbacks
    type Callback = StubGuiCallback;

    fn newsroom_verifying_key(&self) -> Option<&securedrop_protocol_minimal::VerifyingKey> {
        Some(&self.0)
    }

    fn set_newsroom_verifying_key(&mut self, key: securedrop_protocol_minimal::VerifyingKey) {
        // ignore this, we initialize with a key for now for simplicity
        ()
    }

    fn api(&self) -> &Self::NetworkApi {
        &self
    }
}

// "network" api impl that directly interacts with our mock server via the ServerContract api.
impl Api for MockApp<'_> {
    fn request_keys(
        &self,
        req: securedrop_protocol_minimal::wire::core::WelcomeBundleRequest,
    ) -> Result<securedrop_protocol_minimal::wire::core::WelcomeBundle, NetworkError> {
        self.2.borrow().welcome(req)
    }

    fn fetch_challenges(
        &self,
        req: securedrop_protocol_minimal::wire::core::MessageChallengeFetchRequest,
    ) -> Result<securedrop_protocol_minimal::wire::core::MessageChallengeFetchResponse, NetworkError>
    {
        self.2.borrow_mut().challenges(req)
    }

    fn fetch_message(
        &self,
        req: securedrop_protocol_minimal::wire::core::MessageFetchRequest,
    ) -> Result<Option<securedrop_protocol_minimal::Envelope>, NetworkError> {
        Ok(self.2.borrow().handle_message_fetch(req))
    }

    fn submit_message(
        &self,
        req: securedrop_protocol_minimal::Envelope,
    ) -> Result<(), NetworkError> {
        self.2.borrow_mut().message_submit(req)
    }
}

// Example journalist application
pub(crate) struct MockJournalistApp<'b>(pub MockApp<'b>);
impl<'b> MockJournalistApp<'b> {
    pub(crate) fn core(&self) -> &MockApp<'b> {
        &self.0
    }
}
impl<'b> HasRng for MockJournalistApp<'b> {
    type Rng = <MockApp<'b> as HasRng>::Rng;

    fn rng(&mut self) -> &mut Self::Rng {
        self.0.rng()
    }
}
impl JournalistApplicationContract for MockJournalistApp<'_> {}
impl<'c> ApplicationContract for MockJournalistApp<'c> {
    type NetworkApi = <MockApp<'c> as ApplicationContract>::NetworkApi;
    type Protocol = <MockApp<'c> as ApplicationContract>::Protocol;
    type Callback = <MockApp<'c> as ApplicationContract>::Callback;

    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.core().newsroom_verifying_key()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        ()
    }

    fn api(&self) -> &Self::NetworkApi {
        self.core().api()
    }
}

impl Api for MockJournalistApp<'_> {
    fn request_keys(&self, req: WelcomeBundleRequest) -> Result<WelcomeBundle, NetworkError> {
        Api::request_keys(self.core(), req)
    }

    fn fetch_challenges(
        &self,
        req: MessageChallengeFetchRequest,
    ) -> Result<MessageChallengeFetchResponse, NetworkError> {
        Api::fetch_challenges(self.core(), req)
    }

    fn fetch_message(&self, req: MessageFetchRequest) -> Result<Option<Envelope>, NetworkError> {
        Api::fetch_message(self.core(), req)
    }

    fn submit_message(&self, req: Envelope) -> Result<(), NetworkError> {
        Api::submit_message(self.core(), req)
    }
}
impl JournalistApi for MockJournalistApp<'_> {
    fn create_setup_request(
        &self,
        setup: securedrop_protocol_minimal::wire::setup::JournalistSetupRequest,
    ) -> Result<JournalistSetupResponse, anyhow::Error> {
        self.core().2.borrow_mut().setup_journalist(setup)
    }

    fn create_ephemeral_key_request(
        &self,
        kr: securedrop_protocol_minimal::wire::setup::JournalistEphemeralKeyRequest,
    ) -> Result<JournalistEphemeralKeyResponse, anyhow::Error> {
        self.core().2.borrow_mut().handle_ephemeral_key_request(kr)
    }
}
