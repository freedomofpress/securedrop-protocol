//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand::rng;

use securedrop_protocol::journalist::JournalistSession;
use securedrop_protocol::keys::{FPFKeyPair, NewsroomKeyPair};
use securedrop_protocol::messages::setup::{
    JournalistSetupRequest, NewsroomSetupRequest, NewsroomSetupResponse,
};
use securedrop_protocol::server::ServerSession;
use securedrop_protocol::storage::ServerStorage;

/// Step 1: Generate FPF keys
#[test]
fn protocol_step_1_generate_fpf_keys() {
    let mut rng = rng();
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Test signing/verification roundtrip
    let message = b"test message";
    let signature = fpf_keys.sk.sign(message);
    assert!(fpf_keys.vk.verify(message, &signature).is_ok());

    // TODO: test serialization / deserialization round trip once we impl that
}

/// Step 2: Newsroom setup
#[test]
fn protocol_step_2_generate_newsroom_keys() {
    let mut rng = rng();

    // Setup: FPF generates their keys (from previous step)
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Newsroom: Create server session and generate setup request
    let mut server_session = ServerSession::new();
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
    let mut rng = rng();

    // Setup: FPF generates their keys (from step 1)
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Setup: Newsroom creates server session and generates setup request (from step 2)
    let mut server_session = ServerSession::new();
    let newsroom_setup = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    // FPF signs the newsroom's public key (from step 2)
    let setup_response = newsroom_setup
        .sign(&fpf_keys)
        .expect("Signing should not fail");

    // Journalist: Create journalist session and generate setup request
    let journalist_session = JournalistSession::new();
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
