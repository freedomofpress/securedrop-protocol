//! Tests for the core steps of the protocol.
//! These correspond to steps 5-10 of the spec.
use getrandom;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use securedrop_protocol_minimal::api::{Api, JournalistApi};
use securedrop_protocol_minimal::keys::{FPFKeyPair, NewsroomKeyPair};

use securedrop_protocol_minimal::messages::core::SourceJournalistKeyRequest;
use securedrop_protocol_minimal::primitives::MESSAGE_ID_FETCH_SIZE;
use securedrop_protocol_minimal::server::Server;
use securedrop_protocol_minimal::types::{
    Journalist, JournalistPublic, Source, UserPublic, UserSecret,
};

// TODO: better way (eg parameterize as in benchmarks)
pub const DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST: usize = 3;

// Toy implementation purposes
fn get_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random source failed");
    ChaCha20Rng::from_seed(seed)
}

/// Step 5: Source fetches keys and verifies their authenticity
#[test]
fn protocol_step_5_source_fetch_keys() {
    let mut rng = get_rng();

    // Setup: Create server with newsroom and journalist
    let mut server_session = Server::new();

    // Setup newsroom
    let newsroom_setup_request = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    // Store the newsroom verifying key for verification
    let newsroom_verifying_key = newsroom_setup_request.newsroom_verifying_key;

    // Simulate FPF signing (in real implementation, this would be done by FPF)
    let fpf_keypair = FPFKeyPair::new(&mut rng);
    let newsroom_setup_response = newsroom_setup_request
        .sign(&fpf_keypair)
        .expect("Can sign newsroom setup request");

    // Store the FPF signature in the server session for later use
    server_session.set_fpf_signature(newsroom_setup_response.sig);

    // setup journalist (new)
    let journalist = Journalist::new(&mut rng, DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST);

    let journalist_setup_request = journalist
        .create_setup_request()
        .expect("Can create journalist setup request");

    server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Journalist provides ephemeral keys
    let ephemeral_key_request = journalist
        .create_ephemeral_key_request()
        .expect("Can create ephemeral key request");

    assert_eq!(
        ephemeral_key_request.bundles.len(),
        DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST
    );

    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Step 4: Generate source session from passphrase
    let mut source_session = Source::from_passphrase(&[1u8; 32]);

    // Step 5: Source fetches newsroom keys
    let newsroom_key_request = source_session.fetch_newsroom_keys();
    let newsroom_key_response =
        server_session.handle_source_newsroom_key_request(newsroom_key_request);

    // Source handles and verifies the newsroom key response
    source_session
        .handle_newsroom_key_response(&newsroom_key_response, &fpf_keypair.vk)
        .expect("Newsroom key response should be valid");

    // Source fetches journalist keys
    let journalist_key_request = source_session.fetch_journalist_keys();
    let journalist_key_responses =
        server_session.handle_source_journalist_key_request(journalist_key_request, &mut rng);

    // We only have one journalist rn
    assert_eq!(journalist_key_responses.len(), 1);
    let journalist_response = &journalist_key_responses[0];

    // Source handles and verifies the journalist key response
    source_session
        .handle_journalist_key_response(journalist_response, &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    // Verify the journalist's signing key matches our expectation
    // (todo improve this)
    let journalist_public = &journalist.public(0);

    let &jvk = journalist_public.verifying_key();

    assert_eq!(
        journalist_response.journalist.verifying_key().into_bytes(),
        jvk.into_bytes()
    );

    // Verify the journalist's fetch key matches our expectation
    assert_eq!(
        journalist_response
            .journalist
            .fetch_pk()
            .clone()
            .into_bytes(),
        journalist.fetch_keypair().1.clone().into_bytes()
    );

    // Verify the journalist's DH key matches our expectation
    assert_eq!(
        journalist_response.journalist.message_auth_pk().as_bytes(),
        journalist.message_auth_keypair().1.as_bytes()
    );

    // Verify that ephemeral keys were consumed (deleted from server storage)
    // After fetching, the journalist should have no ephemeral keys left
    let journalist_id = server_session
        .find_journalist_id(&jvk)
        .expect("Journalist should be found");
    assert_eq!(
        server_session.ephemeral_keys_count(journalist_id),
        DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST - 1
    );

    // Consume the remaining keys
    for _i in 0..DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST - 1 {
        let _ = server_session
            .handle_source_journalist_key_request(SourceJournalistKeyRequest {}, &mut rng);
    }
    assert!(!server_session.has_ephemeral_keys(journalist_id));

    // Test that subsequent requests return no keys (since they were consumed)
    let empty_journalist_key_request = source_session.fetch_journalist_keys();
    let empty_responses =
        server_session.handle_source_journalist_key_request(empty_journalist_key_request, &mut rng);
    assert_eq!(empty_responses.len(), 0);

    // Test that invalid FPF signatures are rejected
    let wrong_fpf_keypair = FPFKeyPair::new(&mut rng);
    assert!(
        source_session
            .handle_newsroom_key_response(&newsroom_key_response, &wrong_fpf_keypair.vk)
            .is_err()
    );

    // Test that invalid newsroom signatures on journalist keys are rejected
    let wrong_newsroom_keypair = NewsroomKeyPair::new(&mut rng);
    assert!(
        source_session
            .handle_journalist_key_response(journalist_response, &wrong_newsroom_keypair.vk)
            .is_err()
    );
}

/// Step 6: Source submits a message
#[test]
fn protocol_step_6_source_submits_message() {
    let mut rng = get_rng();

    // Setup: Complete steps 1-5 (reuse from previous test)
    let mut server_session = Server::new();

    // Setup newsroom
    let newsroom_setup_request = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    let newsroom_verifying_key = newsroom_setup_request.newsroom_verifying_key;

    let fpf_keypair = FPFKeyPair::new(&mut rng);
    let newsroom_setup_response = newsroom_setup_request
        .sign(&fpf_keypair)
        .expect("Can sign newsroom setup request");

    server_session.set_fpf_signature(newsroom_setup_response.sig);

    // Setup journalist: TODO keybundles somewhere else...
    let mut journalist = Journalist::new(&mut rng, 10);
    // let mut journalist_session = JournalistClient::new(
    //     journalist,
    //     newsroom_verifying_key,
    //     newsroom_setup_response.sig,
    // );
    let journalist_setup_request = journalist
        .create_setup_request()
        .expect("Can create journalist setup request");

    server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Store the newsroom verifying key in the journalist session
    journalist.set_newsroom_verifying_key(newsroom_verifying_key);

    // Journalist provides ephemeral keys
    let ephemeral_key_request = journalist
        .create_ephemeral_key_request()
        .expect("Can create ephemeral key request");

    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Source setup
    // let source = Source::from_passphrase(&[1u8; 32]);
    let mut source = Source::new(&mut rng);

    // Source fetches keys (Step 5)
    let newsroom_key_request = source.fetch_newsroom_keys();
    let newsroom_key_response =
        server_session.handle_source_newsroom_key_request(newsroom_key_request);

    source
        .handle_newsroom_key_response(&newsroom_key_response, &fpf_keypair.vk)
        .expect("Newsroom key response should be valid");

    let journalist_key_request = source.fetch_journalist_keys();
    let journalist_key_responses =
        server_session.handle_source_journalist_key_request(journalist_key_request, &mut rng);

    let journalist_response = &journalist_key_responses[0];

    let journalist_public = &journalist_response.journalist;

    source
        .handle_journalist_key_response(journalist_response, &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    // Step 6: Source submits a message
    let message_content = b"Hello, this is a test message!";
    let message = source
        .submit_message(&mut rng, message_content, &source, journalist_public)
        .expect("Can submit message");

    // Submit the message to the server
    let message_id = server_session
        .handle_message_submit(message.clone())
        .expect("Can handle message submission");

    // Verify that the message was stored
    assert!(server_session.has_message(&message_id));
}

/// Step 7: Privacy-preserving message ID fetch
#[test]
fn protocol_step_7_message_id_fetch() {
    let mut rng = get_rng();

    // Setup: Complete steps 1-6 (reuse from previous test)
    let mut server_session = Server::new();

    // Setup newsroom
    let newsroom_setup_request = server_session
        .create_newsroom_setup_request(&mut rng)
        .expect("Can create newsroom setup request");

    let newsroom_verifying_key = newsroom_setup_request.newsroom_verifying_key;

    let fpf_keypair = FPFKeyPair::new(&mut rng);
    let newsroom_setup_response = newsroom_setup_request
        .sign(&fpf_keypair)
        .expect("Can sign newsroom setup request");

    server_session.set_fpf_signature(newsroom_setup_response.sig);

    // Setup journalist : TODO keybundles
    let mut journalist = Journalist::new(&mut rng, 10);
    // let mut journalist_session = JournalistClient::new(
    //     journalist,
    //     newsroom_verifying_key,
    //     newsroom_setup_response.sig,
    // );
    let journalist_setup_request = journalist
        .create_setup_request()
        .expect("Can create journalist setup request");

    server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Store the newsroom verifying key in the journalist session
    journalist.set_newsroom_verifying_key(newsroom_verifying_key);

    // Journalist provides ephemeral keys
    let ephemeral_key_request = journalist
        .create_ephemeral_key_request()
        .expect("Can create ephemeral key request");

    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Source setup
    let mut source = Source::from_passphrase(&[1u8; 32]);

    // Source fetches keys (Step 5)
    let newsroom_key_request = source.fetch_newsroom_keys();
    let newsroom_key_response =
        server_session.handle_source_newsroom_key_request(newsroom_key_request);

    source
        .handle_newsroom_key_response(&newsroom_key_response, &fpf_keypair.vk)
        .expect("Newsroom key response should be valid");

    let journalist_key_request = source.fetch_journalist_keys();
    let journalist_key_responses =
        server_session.handle_source_journalist_key_request(journalist_key_request, &mut rng);

    let journalist_response = &journalist_key_responses[0];

    source
        .handle_journalist_key_response(journalist_response, &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    // Submit a message (Step 6)
    let message_content = b"Hello, this is a test message!";
    let message = source
        .submit_message(
            &mut rng,
            message_content,
            &source,
            &journalist_response.journalist,
        )
        .expect("Can submit message");

    let message_id = server_session
        .handle_message_submit(message.clone())
        .expect("Can handle message submission");

    // Step 7: Test message ID fetch from journalist perspective
    let journalist_fetch_request = journalist.fetch_message_ids(&mut rng);
    let journalist_fetch_response = server_session
        .handle_request_challenges(journalist_fetch_request, &mut rng)
        .expect("should be able to fetch message IDs");

    // Verify response structure
    assert_eq!(journalist_fetch_response.count, MESSAGE_ID_FETCH_SIZE);
    assert_eq!(
        journalist_fetch_response.messages.len(),
        MESSAGE_ID_FETCH_SIZE
    );

    // Process the response to extract message IDs
    let journalist_message_ids = journalist
        .solve_fetch_challenges(journalist_fetch_response.messages)
        .expect("Can process message ID response");

    // Verify that the journalist can also find the message ID
    assert!(
        journalist_message_ids.contains(&message_id),
        "Journalist should find the message ID"
    );

    // Verify privacy properties: response size is always the same
    let empty_fetch_request = source.fetch_message_ids(&mut rng);
    let empty_fetch_response = server_session
        .handle_request_challenges(empty_fetch_request, &mut rng)
        .expect("we should be able to handle message ID fetch");
    assert_eq!(empty_fetch_response.count, MESSAGE_ID_FETCH_SIZE);
    assert_eq!(empty_fetch_response.messages.len(), MESSAGE_ID_FETCH_SIZE);
}
