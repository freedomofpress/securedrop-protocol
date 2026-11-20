use crate::common::mocks::{Server, ServerStorage};

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use securedrop_protocol_minimal::api::{JournalistApi, ServerContract};
use securedrop_protocol_minimal::keys::{FPFKeyPair, NewsroomKeyPair, fpf};
use securedrop_protocol_minimal::sign::{FpfOnNewsroom, Signature};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistSetupRequest,
};

use securedrop_protocol_minimal::VerifyingKey;
use securedrop_protocol_minimal::{DHPublicKey, Enrollable};
use securedrop_protocol_minimal::{Journalist, Source, UserPublic, UserSecret};

// Toy implementation purposes
pub(crate) fn get_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    #[allow(clippy::disallowed_methods)]
    getrandom::fill(&mut seed).expect("OS random source failed");
    ChaCha20Rng::from_seed(seed)
}

// Set up server with new keypair and root-signed key.
pub(crate) fn setup_server(
    mut rng: ChaCha20Rng,
    fpf_keys: &FPFKeyPair,
) -> (Server, VerifyingKey, Signature<FpfOnNewsroom>) {
    // Newsroom: Create server session and generate setup request (pubkey)

    let in_mem_storage = ServerStorage::new();

    let mut server_session = Server::new(in_mem_storage, None, None, rng);

    let newsroom_setup = server_session
        .create_newsroom_setup_request()
        .expect("Can create newsroom setup request");

    // Store the newsroom verifying key for verification
    let newsroom_vk = &newsroom_setup.newsroom_verifying_key.clone();

    // Sign the newsroom's public key
    let setup_response = newsroom_setup
        .sign(&fpf_keys)
        .expect("Signing should not fail");

    assert!(
        fpf_keys
            .verifying_key()
            .verify(&newsroom_vk.clone().into_bytes(), &setup_response.sig)
            .is_ok()
    );

    server_session.set_fpf_signature(setup_response.sig);

    (server_session, *newsroom_vk, setup_response.sig)
}
