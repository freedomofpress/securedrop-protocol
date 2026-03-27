//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use securedrop_protocol_minimal::api::{Api, JournalistApi};
use securedrop_protocol_minimal::encrypt_decrypt::LEN_DH_ITEM;
use securedrop_protocol_minimal::keys::FPFKeyPair;
use securedrop_protocol_minimal::messages::setup::{
    JournalistEphemeralKeyRequest, JournalistSetupRequest,
};
use securedrop_protocol_minimal::sign::{FpfOnNewsroom, Signature};

use securedrop_protocol_minimal::VerifyingKey;
use securedrop_protocol_minimal::server::Server;
use securedrop_protocol_minimal::{Journalist, Source, UserPublic, UserSecret};

// Toy implementation purposes
fn get_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source failed");
    ChaCha20Rng::from_seed(seed)
}

fn setup_fpf_key<R: CryptoRng + RngCore>(mut rng: R) -> FPFKeyPair {
    FPFKeyPair::new(&mut rng).expect("FPF key generation failed")
}

// Helper - set up server, set up newsroom key, and return server session
fn setup_server<R: CryptoRng + RngCore>(
    mut rng: R,
    fpf_keys: &FPFKeyPair,
) -> (Server, VerifyingKey, Signature<FpfOnNewsroom>) {
    // Newsroom: Create server session and generate setup request (pubkey)
    let mut server_session = Server::new();
    let newsroom_setup = server_session
        .create_newsroom_setup_request(&mut rng)
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

    (server_session, *newsroom_vk, setup_response.sig)
}

// todo: easy to mix up fpf pubkey and nr pubkey here, enforce with types
fn setup_journalist<R: RngCore + CryptoRng>(
    mut rng: R,
    num_keybundles: usize,
    newsroom_pubkey: &VerifyingKey,
    fpf_pubkey: &VerifyingKey,
    fpf_signature: &Signature<FpfOnNewsroom>,
) -> (Journalist, JournalistSetupRequest) {
    let mut journalist = Journalist::new(&mut rng, num_keybundles);

    // Journalist: verify nr key correctly signed, then store it.
    // Then request enrollment
    assert!(
        fpf_pubkey
            .verify(&newsroom_pubkey.into_bytes(), fpf_signature)
            .is_ok()
    );
    journalist.set_newsroom_verifying_key(*newsroom_pubkey);

    let journalist_setup_request = journalist
        .create_setup_request()
        .expect("Can create journalist setup request");

    (journalist, journalist_setup_request)
}

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

    let (_, newsroom_vk, fpf_sig) = setup_server(rng, &fpf_keys);

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

    let (mut server_session, newsroom_vk, fpf_sig) = setup_server(&mut rng, &fpf_keys);

    assert!(
        fpf_keys
            .verifying_key()
            .verify(&newsroom_vk.into_bytes(), &fpf_sig)
            .is_ok()
    );

    let vk = newsroom_vk.clone();

    // store fpf signature over newsroom vk in session
    server_session.set_fpf_signature(fpf_sig);

    // Journalist: Create journalist session and generate setup request
    // todo keybundles
    let (_, journalist_setup_request) =
        setup_journalist(rng, 10, &vk, &fpf_keys.verifying_key(), &fpf_sig);

    // Extract enrollment bundle for verification before moving the request
    let enrollment_bundle = journalist_setup_request.enrollment.clone();

    // Newsroom: Process journalist setup request and sign the enrollment bundle
    let journalist_setup_response = server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Journalist: Verify newsroom signature on journalist signing pubkey.
    let pubkey_bytes = enrollment_bundle.keys.0.into_bytes();
    let newsroom_vk = server_session
        .newsroom_verifying_key()
        .expect("Newsroom keys should be available");
    assert!(
        newsroom_vk
            .verify(&pubkey_bytes, &journalist_setup_response.sig)
            .is_ok()
    );

    // Test that wrong bundle bytes fail verification.
    let wrong_bundle_bytes = [0u8; 96];
    assert!(
        newsroom_vk
            .verify(&wrong_bundle_bytes, &journalist_setup_response.sig)
            .is_err()
    );

    // Journalist: Verify the journalist self-signature on pubkey enrollment bundle.
    let enrollment_bundle_bytes = enrollment_bundle.bundle;
    let self_signature = enrollment_bundle.selfsig;

    let _ = server_session
        .find_journalist_id(&enrollment_bundle.keys.0)
        .expect("Journalist id should be available for enrolled signing key");
    assert!(
        enrollment_bundle
            .keys
            .0
            .verify(enrollment_bundle_bytes.as_bytes(), &self_signature)
            .is_ok()
    );

    // Test that wrong journalist signature bytes fail self-sig verification.
    assert!(
        enrollment_bundle
            .keys
            .0
            .verify(&wrong_bundle_bytes, &self_signature)
            .is_err()
    );
}

/// Step 3.2: Journalist ephemeral key replenishment
#[test]
fn protocol_step_3_2_journalist_ephemeral_keys() {
    let mut rng = get_rng();

    // Setup: FPF generates their keys (Step 1)
    let fpf_keys = setup_fpf_key(&mut rng);

    // Setup: Newsroom creates server session and generates setup request (Step 2)
    let (mut server_session, vk_nr, sig) = setup_server(&mut rng, &fpf_keys);

    let (journalist, journalist_setup_request) =
        setup_journalist(&mut rng, 10, &vk_nr, &fpf_keys.verifying_key(), &sig);

    // Extract enrollment bundle for verification before moving the request
    let enrollment_bundle = journalist_setup_request.enrollment.clone();

    // Newsroom: Process journalist setup request and sign the enrollment bundle
    let journalist_setup_response = server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Journalist: Verify newsroom signature on journalist signing pubkey.
    let pubkey_bytes = enrollment_bundle.keys.0.into_bytes();
    let newsroom_vk = server_session
        .newsroom_verifying_key()
        .expect("Newsroom keys should be available");
    assert!(
        newsroom_vk
            .verify(&pubkey_bytes, &journalist_setup_response.sig)
            .is_ok()
    );

    // Journalist: Verify the journalist self-signature on pubkey enrollment bundle
    let enrollment_bundle_bytes = enrollment_bundle.bundle;
    let self_signature = enrollment_bundle.selfsig;

    let _ = server_session
        .find_journalist_id(&enrollment_bundle.keys.0)
        .expect("Journalist id should be available for enrolled signing key");
    assert!(
        enrollment_bundle
            .keys
            .0
            .verify(enrollment_bundle_bytes.as_bytes(), &self_signature)
            .is_ok()
    );

    // Step 3.2: Journalist generates ephemeral keys and signs them
    // Journalist creates ephemeral key request
    let ephemeral_key_request = journalist
        .create_ephemeral_key_request()
        .expect("Can create ephemeral key request");

    let bundles = ephemeral_key_request.bundles.clone();

    // Server: Process ephemeral key request, including verification
    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Test that server rejects ephemeral keys from unknown journalist
    let unknown_journalist_request = JournalistEphemeralKeyRequest {
        verifying_key: FPFKeyPair::new(&mut rng)
            .expect("key generation failed")
            .verifying_key(),
        bundles: bundles,
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
    let source = Source::new(&mut rng);
    assert_eq!(source.num_bundles(), 1);

    let source_public = source.public();
    let pass = source.passphrase();
    let source2 = Source::from_passphrase(pass);
    assert_ne!(source_public.fetch_pk().into_bytes(), [0u8; LEN_DH_ITEM]);
    assert_ne!(
        source_public.message_auth_pk().as_bytes(),
        &[0u8; LEN_DH_ITEM]
    );
    assert_eq!(pass, source2.passphrase());
    assert_eq!(
        source_public.fetch_pk().into_bytes(),
        source2.public().fetch_pk().into_bytes()
    );
}
