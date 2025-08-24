//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand::rng;

use securedrop_protocol::keys::{FPFKeyPair, NewsroomKeyPair};
use securedrop_protocol::messages::setup::{NewsroomSetupRequest, NewsroomSetupResponse};
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

    // Newsroom: Generate their signing key pair
    let newsroom_keys = NewsroomKeyPair::new(&mut rng);

    // Newsroom: Create newsroom setup request with the newsroom's public key
    let newsroom_setup = NewsroomSetupRequest {
        newsroom_verifying_key: newsroom_keys.vk,
    };

    // Sign the newsroom's public key
    let setup_response = newsroom_setup
        .sign(&fpf_keys)
        .expect("Signing should not fail");

    // Newsroom: Verify the FPF signature on the newsroom's public key
    let newsroom_pk_bytes = newsroom_keys.vk.into_bytes();
    assert!(
        fpf_keys
            .vk
            .verify(&newsroom_pk_bytes, &setup_response.sig)
            .is_ok()
    );
}
