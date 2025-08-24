//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand::rng;

use securedrop_protocol::keys::{FPFKeyPair, NewsroomKeyPair};

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

    // FPF: Sign the newsroom's public key
    let newsroom_pk_bytes = newsroom_keys.vk.into_bytes();
    let fpf_signature = fpf_keys.sk.sign(&newsroom_pk_bytes);

    // Newsroom: Verify the FPF signature on the newsroom's public key
    assert!(
        fpf_keys
            .vk
            .verify(&newsroom_pk_bytes, &fpf_signature)
            .is_ok()
    );

    // Test that wrong public key fails verification
    let wrong_pk_bytes = [0u8; 32];
    assert!(fpf_keys.vk.verify(&wrong_pk_bytes, &fpf_signature).is_err());
}
