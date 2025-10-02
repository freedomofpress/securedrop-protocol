//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use securedrop_protocol::journalist::JournalistClient;
use securedrop_protocol::keys::{
    FPFKeyPair, JournalistOneTimePublicKeys, JournalistSigningKeyPair, NewsroomKeyPair,
    SourceKeyBundle,
};
use securedrop_protocol::messages::setup::{
    JournalistRefreshRequest, JournalistSetupRequest, NewsroomSetupRequest, NewsroomSetupResponse,
};
use securedrop_protocol::server::Server;
use securedrop_protocol::source::SourceClient;
use securedrop_protocol::storage::ServerStorage;

// Toy implementation purposes
fn get_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source failed");
    ChaCha20Rng::from_seed(seed)
}

/// Step 1: Generate FPF keys
#[test]
fn protocol_step_1_generate_fpf_keys() {
    let mut rng = get_rng();
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Test signing/verification roundtrip
    let message = b"test message";
    let signature = fpf_keys.sk.sign(message);
    assert!(fpf_keys.vk.verify(message, &signature).is_ok());
}

/// Step 2: Newsroom setup
#[test]
fn protocol_step_2_generate_newsroom_keys() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (from previous step)
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Newsroom: Create server session and generate setup request
    let mut server_session = Server::new();
    let newsroom_setup = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    // Store the newsroom verifying key for verification
    let newsroom_vk = newsroom_setup.newsroom_verifying_key;

    // Sign the newsroom's public key
    let setup_response = newsroom_setup
        .sign(&fpf_keys)
        .expect("Signing should not fail");

    // Newsroom: Verify the FPF signature on the newsroom's public key
    let newsroom_pk_bytes = newsroom_vk.into_bytes();
    assert!(
        fpf_keys
            .vk
            .verify(&newsroom_pk_bytes, &setup_response.sig)
            .is_ok()
    );
}

/// Step 3.1: Journalist enrollment
#[test]
fn protocol_step_3_1_journalist_enrollment() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (from step 1)
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Setup: Newsroom creates server session and generates setup request (from step 2)
    let mut server_session = Server::new();
    let newsroom_setup = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    // FPF signs the newsroom's public key (from step 2)
    let _setup_response = newsroom_setup
        .sign(&fpf_keys)
        .expect("Signing should not fail");

    // Journalist: Create journalist session and generate setup request
    let mut journalist_session = JournalistClient::new();
    let journalist_setup_request = journalist_session
        .create_setup_request(&mut rng)
        .expect("Can create journalist setup request");

    // Extract enrollment bundle for verification before moving the request
    let enrollment_bundle = journalist_setup_request.enrollment_key_bundle.clone();

    // Newsroom: Process journalist setup request and sign the enrollment bundle
    let journalist_setup_response = server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Journalist: Verify the newsroom signature on the enrollment bundle
    let enrollment_bundle_bytes = enrollment_bundle.into_bytes();
    let newsroom_vk = server_session
        .get_newsroom_verifying_key()
        .expect("Newsroom keys should be available");
    assert!(
        newsroom_vk
            .verify(&enrollment_bundle_bytes, &journalist_setup_response.sig)
            .is_ok()
    );

    // Test that wrong bundle bytes fail verification
    let wrong_bundle_bytes = [0u8; 96];
    assert!(
        newsroom_vk
            .verify(&wrong_bundle_bytes, &journalist_setup_response.sig)
            .is_err()
    );
}

/// Step 3.2: Journalist ephemeral key replenishment
#[test]
fn protocol_step_3_2_journalist_ephemeral_keys() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (Step 1)
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Setup: Newsroom creates server session and generates setup request (Step 2)
    let mut server_session = Server::new();
    let newsroom_setup = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    // FPF signs the newsroom's public key (Step 2)
    let _setup_response = newsroom_setup
        .sign(&fpf_keys)
        .expect("Signing should not fail");

    // Setup: Journalist enrollment (Step 3.1)
    let mut journalist_session = JournalistClient::new();
    let journalist_setup_request = journalist_session
        .create_setup_request(&mut rng)
        .expect("Can create journalist setup request");

    // Extract enrollment bundle for verification before moving the request
    let enrollment_bundle = journalist_setup_request.enrollment_key_bundle.clone();

    // Newsroom: Process journalist setup request and sign the enrollment bundle
    let journalist_setup_response = server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Journalist: Verify the newsroom signature on the enrollment bundle
    let enrollment_bundle_bytes = enrollment_bundle.into_bytes();
    let newsroom_vk = server_session
        .get_newsroom_verifying_key()
        .expect("Newsroom keys should be available");
    assert!(
        newsroom_vk
            .verify(&enrollment_bundle_bytes, &journalist_setup_response.sig)
            .is_ok()
    );

    // Step 3.2: Journalist generates ephemeral keys and signs them
    // Journalist creates ephemeral key request
    let ephemeral_key_request = journalist_session
        .create_ephemeral_key_request(&mut rng)
        .expect("Can create ephemeral key request");

    // Get the verifying key for verification
    let journalist_verifying_key = journalist_session
        .verifying_key()
        .expect("Verifying key should be available after setup");

    // Extract bundle for verification before moving the request
    let ephemeral_bundle = ephemeral_key_request.ephemeral_key_bundle.clone();

    // Server: Process ephemeral key request
    let ephemeral_key_response = server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    assert!(ephemeral_key_response.success);

    // Get the ephemeral public keys from the bundle
    let ephemeral_public_keys = &ephemeral_bundle.public_keys;

    // Verify the journalist's signature on the ephemeral keys
    let ephemeral_keys_bytes = ephemeral_public_keys.clone().into_bytes();

    assert!(
        journalist_verifying_key
            .verify(&ephemeral_keys_bytes, &ephemeral_bundle.signature)
            .is_ok()
    );

    // Test that wrong ephemeral keys bytes fail verification
    let wrong_ephemeral_bytes = [0u8; 96];
    assert!(
        journalist_verifying_key
            .verify(&wrong_ephemeral_bytes, &ephemeral_bundle.signature)
            .is_err()
    );

    // Test that server rejects ephemeral keys from unknown journalist
    let unknown_journalist_request = JournalistRefreshRequest {
        journalist_verifying_key: FPFKeyPair::new(&mut rng).vk, // Use a different key
        ephemeral_key_bundle: ephemeral_bundle.clone(),
    };
    assert!(
        server_session
            .handle_ephemeral_key_request(unknown_journalist_request)
            .is_err()
    );
}

/// Step 4: Source setup - derive keys from passphrase
#[test]
fn protocol_step_4_source_setup() {
    let mut rng = get_rng();

    // Initialize source session with new passphrase (Protocol Step 4)
    let (passphrase, source_session) = SourceClient::initialize_with_passphrase(&mut rng);

    // Verify that all keys were generated
    assert_eq!(passphrase.passphrase.len(), 32);
    assert!(source_session.key_bundle().is_some());
}
