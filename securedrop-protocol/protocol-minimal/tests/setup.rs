//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use securedrop_protocol_minimal::api::{
    JournalistApi, JournalistApplicationContract, ServerContract,
};
use securedrop_protocol_minimal::keys::{FPFKeyPair, NewsroomKeyPair, fpf};
use securedrop_protocol_minimal::sign::{FpfOnNewsroom, Signature};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistSetupRequest,
};

use securedrop_protocol_minimal::VerifyingKey;
use securedrop_protocol_minimal::{DHPublicKey, Enrollable};
use securedrop_protocol_minimal::{Journalist, Source, UserPublic, UserSecret};

mod common;
use common::mocks::Server;
use common::utils::{get_rng, setup_server};

use crate::common::mocks::{MockApp, MockJournalistApp};

/// Step 1: Generate FPF keys
#[test]
fn protocol_step_1_generate_fpf_keys() {
    let mut rng = get_rng();
    let fpf_keys = FPFKeyPair::new(&mut rng).expect("FPF key generation failed");

    let message = b"test message";
    let signature = fpf_keys.sign::<FpfOnNewsroom>(message);
    assert!(fpf_keys.verifying_key().verify(message, &signature).is_ok());
}

/// Step 2: Newsroom setup
#[test]
fn protocol_step_2_generate_newsroom_keys() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (from previous step)
    let fpf_keys = FPFKeyPair::new(&mut rng).expect("FPF key generation failed");

    let (_, newsroom_vk, fpf_sig) = setup_server(get_rng(), &fpf_keys);

    let newsroom_pk_bytes = newsroom_vk.into_bytes();
    assert!(
        fpf_keys
            .verifying_key()
            .verify(&newsroom_pk_bytes, &fpf_sig)
            .is_ok()
    );
}

/// Step 3.1: Journalist enrollment
#[test]
fn protocol_step_3_1_journalist_enrollment() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (from step 1)
    let fpf_keys = FPFKeyPair::new(&mut rng).expect("FPF key generation failed");

    // set up mock server with new key signed by fpf key
    let (mut server_session, newsroom_vk, fpf_sig) = setup_server(get_rng(), &fpf_keys);

    assert!(
        fpf_keys
            .verifying_key()
            .verify(&newsroom_vk.into_bytes(), &fpf_sig)
            .is_ok()
    );

    let mut j_rng = get_rng();
    let journalist_keys = Journalist::new(&mut j_rng, 10);
    let journalist_client = MockJournalistApp(MockApp::new(
        newsroom_vk.clone(),
        j_rng,
        &mut server_session,
    ));

    // Journalist create enrollment request
    let enrollment_bundle = journalist_client
        .prepare_enrollment(&journalist_keys)
        .expect("Journalist can prepare enrollment bundle");
    let enrollment_bundle_copy = enrollment_bundle.enrollment.clone(); // just for test purposes

    // Journalist enroll
    let resp = journalist_client
        .create_setup_request(enrollment_bundle)
        .expect("Journalist can enroll at the server");

    // Journalist check signature over long-term key after enrolled
    // (Note, NR signature over long-term key would happen offline)
    let pubkey_bytes = enrollment_bundle_copy.verification_key.into_bytes();
    assert!(newsroom_vk.verify(&pubkey_bytes, &resp.sig).is_ok());
    assert_eq!(pubkey_bytes, journalist_keys.signing_key().into_bytes());

    // Test that wrong bundle bytes fail verification.
    let wrong_bundle_bytes = [0u8; 96];
    assert!(newsroom_vk.verify(&wrong_bundle_bytes, &resp.sig).is_err());

    // Journalist: Verify the journalist self-signature on pubkey enrollment bundle.
    let enrollment_bundle_bytes = enrollment_bundle_copy.bundle.bundle_bytes();
    let self_signature = enrollment_bundle_copy.bundle.selfsig;

    let _ = server_session
        .find_journalist_id(&enrollment_bundle_copy.verification_key)
        .expect("Journalist id should be available for enrolled signing key");
    assert!(
        enrollment_bundle_copy
            .verification_key
            .verify(&enrollment_bundle_bytes, &self_signature)
            .is_ok()
    );

    // Test that wrong journalist signature bytes fail self-sig verification.
    assert!(
        enrollment_bundle_copy
            .verification_key
            .verify(&wrong_bundle_bytes, &self_signature)
            .is_err()
    );
}

/// Step 3.2: Journalist ephemeral key replenishment
#[test]
fn protocol_step_3_2_journalist_ephemeral_keys() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (from step 1)
    let fpf_keys = FPFKeyPair::new(&mut rng).expect("FPF key generation failed");

    // set up mock server with new key signed by fpf key
    let (mut server_session, newsroom_vk, fpf_sig) = setup_server(get_rng(), &fpf_keys);

    assert!(
        fpf_keys
            .verifying_key()
            .verify(&newsroom_vk.into_bytes(), &fpf_sig)
            .is_ok()
    );

    let mut j_rng = get_rng();
    let journalist_keys = Journalist::new(&mut j_rng, 10);
    let journalist_client = MockJournalistApp(MockApp::new(
        newsroom_vk.clone(),
        j_rng,
        &mut server_session,
    ));

    // Journalist create enrollment request
    let enrollment_bundle = journalist_client
        .prepare_enrollment(&journalist_keys)
        .expect("Journalist can prepare enrollment bundle");
    // Journalist enroll
    let enrollment_bundle_copy = enrollment_bundle.enrollment.bundle.clone();
    let enrollment_bundle_vk_copy = enrollment_bundle.enrollment.verification_key.clone();
    let resp = journalist_client
        .create_setup_request(enrollment_bundle)
        .expect("Journalist can enroll at the server");

    assert!(
        enrollment_bundle_vk_copy
            .verify(
                &enrollment_bundle_copy.bundle_bytes(),
                &enrollment_bundle_copy.selfsig
            )
            .is_ok()
    );

    // Step 3.2: Journalist generates ephemeral keys and signs them
    // Journalist creates ephemeral key request

    let keybundles = journalist_client
        .prepare_keybundles(&journalist_keys)
        .expect("Can prepare short-lived key bundles");
    // Journalist Upload keyundles
    let response = journalist_client
        .create_ephemeral_key_request(keybundles)
        .expect("Can replenish key bundles");

    // Non-enrolled journalist cannot upload short-lived keys
    let unknown_journalist = Journalist::new(&mut get_rng(), 5);
    let some_other_keys = journalist_client
        .prepare_keybundles(&unknown_journalist)
        .expect("even imposters can do local keygen");

    assert!(
        journalist_client
            .create_ephemeral_key_request(some_other_keys)
            .is_err()
    );

    // Non-enrolled journalist key cannot enroll validly-signed ephemeral keys from other user
    let unknown_journalist_request = JournalistEphemeralKeyRequest {
        verifying_key: *unknown_journalist.signing_key(),
        bundles: journalist_keys.signed_keybundles(),
    };

    // Test that server won't accept keys with unknown pubkey
    assert!(
        journalist_client
            .create_ephemeral_key_request(unknown_journalist_request)
            .is_err()
    );
}

/// Step 4: Source setup - derive keys from passphrase
#[test]
fn protocol_step_4_source_setup() {
    let mut rng = get_rng();

    // Initialize source session with new passphrase (Protocol Step 4)
    let source = Source::new(&mut rng);
    assert_eq!(source.num_bundles(), 1);

    let source_public = source.public();
    let pass = source.passphrase();
    let source2 = Source::from_passphrase(pass).expect("generated mnemonic is valid");
    assert_ne!(
        source_public.fetch_pk().into_bytes(),
        [0u8; DHPublicKey::LEN]
    );
    assert_ne!(
        source_public.message_auth_pk().as_bytes(),
        &[0u8; DHPublicKey::LEN]
    );
    assert_eq!(pass, source2.passphrase());
    assert_eq!(
        source_public.fetch_pk().into_bytes(),
        source2.public().fetch_pk().into_bytes()
    );
}
