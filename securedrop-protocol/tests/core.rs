//! Tests for the core steps of the protocol.
//! These correspond to steps 5-10 of the spec.

use rand::rng;

use securedrop_protocol::Client;
use securedrop_protocol::journalist::JournalistClient;
use securedrop_protocol::keys::{
    FPFKeyPair, JournalistEphemeralPublicKeys, JournalistSigningKeyPair, NewsroomKeyPair,
    SourceKeyBundle,
};
use securedrop_protocol::messages::setup::{
    JournalistRefreshRequest, JournalistSetupRequest, NewsroomSetupRequest, NewsroomSetupResponse,
};
use securedrop_protocol::primitives::MESSAGE_ID_FETCH_SIZE;
use securedrop_protocol::server::Server;
use securedrop_protocol::source::SourceClient;
use securedrop_protocol::storage::ServerStorage;

/// Step 5: Source fetches keys and verifies their authenticity
#[test]
fn protocol_step_5_source_fetch_keys() {
    let mut rng = rng();

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

    // Setup journalist
    let mut journalist_session = JournalistClient::new();
    let journalist_setup_request = journalist_session
        .create_setup_request(&mut rng)
        .expect("Can create journalist setup request");

    server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Journalist provides ephemeral keys
    let ephemeral_key_request = journalist_session
        .create_ephemeral_key_request(&mut rng)
        .expect("Can create ephemeral key request");

    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Step 4: Generate source session from passphrase
    let mut source_session = SourceClient::from_passphrase(&[1u8; 32]);

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
    let journalist_response = &journalist_key_responses[0];

    // Source handles and verifies the journalist key response
    source_session
        .handle_journalist_key_response(journalist_response, &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    // Verify the journalist's signing key matches our expectation
    let journalist_verifying_key = journalist_session
        .verifying_key()
        .expect("Journalist should have verifying key");
    assert_eq!(
        journalist_response.journalist_sig_pk.into_bytes(),
        journalist_verifying_key.into_bytes()
    );

    // Verify the journalist's fetch key matches our expectation
    let journalist_fetch_key = journalist_session
        .fetching_key()
        .expect("Journalist should have fetching key");
    assert_eq!(
        journalist_response.journalist_fetch_pk.clone().into_bytes(),
        journalist_fetch_key.clone().into_bytes()
    );

    // Verify the journalist's DH key matches our expectation
    let journalist_dh_key = journalist_session
        .dh_key()
        .expect("Journalist should have DH key");
    assert_eq!(
        journalist_response.journalist_dh_pk.clone().into_bytes(),
        journalist_dh_key.clone().into_bytes()
    );

    // Verify that ephemeral keys were consumed (deleted from server storage)
    // After fetching, the journalist should have no ephemeral keys left
    let journalist_id = server_session
        .find_journalist_id(journalist_verifying_key)
        .expect("Journalist should be found");
    assert_eq!(server_session.ephemeral_keys_count(journalist_id), 0);
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
    let mut rng = rng();

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

    // Setup journalist
    let mut journalist_session = JournalistClient::new();
    let journalist_setup_request = journalist_session
        .create_setup_request(&mut rng)
        .expect("Can create journalist setup request");

    server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Store the newsroom verifying key in the journalist session
    journalist_session.set_newsroom_verifying_key(newsroom_verifying_key);

    // Journalist provides ephemeral keys
    let ephemeral_key_request = journalist_session
        .create_ephemeral_key_request(&mut rng)
        .expect("Can create ephemeral key request");

    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Source setup
    let mut source_session = SourceClient::from_passphrase(&[1u8; 32]);

    // Source fetches keys (Step 5)
    let newsroom_key_request = source_session.fetch_newsroom_keys();
    let newsroom_key_response =
        server_session.handle_source_newsroom_key_request(newsroom_key_request);

    source_session
        .handle_newsroom_key_response(&newsroom_key_response, &fpf_keypair.vk)
        .expect("Newsroom key response should be valid");

    let journalist_key_request = source_session.fetch_journalist_keys();
    let journalist_key_responses =
        server_session.handle_source_journalist_key_request(journalist_key_request, &mut rng);

    let journalist_response = &journalist_key_responses[0];

    source_session
        .handle_journalist_key_response(journalist_response, &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    // Step 6: Source submits a message
    let message_content = b"Hello, this is a test message!";
    let messages = source_session
        .submit_message(
            message_content.to_vec(),
            &journalist_key_responses,
            &mut rng,
        )
        .expect("Can submit message");

    // Verify that we got one message per journalist
    assert_eq!(messages.len(), 1);

    let message = &messages[0];

    // Submit the message to the server
    let message_id = server_session
        .handle_message_submit(message.clone())
        .expect("Can handle message submission");

    // Verify that the message was stored
    assert!(server_session.has_message(&message_id));
}

#[ignore]
/// Step 7: Privacy-preserving message ID fetch
#[test]
fn protocol_step_7_message_id_fetch() {
    let mut rng = rng();

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

    // Setup journalist
    let mut journalist_session = JournalistClient::new();
    let journalist_setup_request = journalist_session
        .create_setup_request(&mut rng)
        .expect("Can create journalist setup request");

    server_session
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // Store the newsroom verifying key in the journalist session
    journalist_session.set_newsroom_verifying_key(newsroom_verifying_key);

    // Journalist provides ephemeral keys
    let ephemeral_key_request = journalist_session
        .create_ephemeral_key_request(&mut rng)
        .expect("Can create ephemeral key request");

    server_session
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // Source setup
    let mut source_session = SourceClient::from_passphrase(&[1u8; 32]);

    // Source fetches keys (Step 5)
    let newsroom_key_request = source_session.fetch_newsroom_keys();
    let newsroom_key_response =
        server_session.handle_source_newsroom_key_request(newsroom_key_request);

    source_session
        .handle_newsroom_key_response(&newsroom_key_response, &fpf_keypair.vk)
        .expect("Newsroom key response should be valid");

    let journalist_key_request = source_session.fetch_journalist_keys();
    let journalist_key_responses =
        server_session.handle_source_journalist_key_request(journalist_key_request, &mut rng);

    let journalist_response = &journalist_key_responses[0];

    source_session
        .handle_journalist_key_response(journalist_response, &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    // Submit a message (Step 6)
    let message_content = b"Hello, this is a test message!";
    let messages = source_session
        .submit_message(
            message_content.to_vec(),
            &journalist_key_responses,
            &mut rng,
        )
        .expect("Can submit message");

    let message = &messages[0];
    let message_id = server_session
        .handle_message_submit(message.clone())
        .expect("Can handle message submission");

    // Step 7: Test message ID fetch from journalist perspective
    let journalist_fetch_request = journalist_session.fetch_message_ids(&mut rng);
    let journalist_fetch_response = server_session
        .handle_message_id_fetch(journalist_fetch_request, &mut rng)
        .expect("should be able to fetch message IDs");

    // Verify response structure
    assert_eq!(journalist_fetch_response.count, MESSAGE_ID_FETCH_SIZE);
    assert_eq!(
        journalist_fetch_response.messages.len(),
        MESSAGE_ID_FETCH_SIZE
    );

    // Process the response to extract message IDs
    let journalist_message_ids = journalist_session
        .process_message_id_response(&journalist_fetch_response)
        .expect("Can process message ID response");

    // Verify that the journalist can also find the message ID
    assert!(
        journalist_message_ids.contains(&message_id),
        "Journalist should find the message ID"
    );

    // Verify privacy properties: response size is always the same
    let empty_fetch_request = source_session.fetch_message_ids(&mut rng);
    let empty_fetch_response = server_session
        .handle_message_id_fetch(empty_fetch_request, &mut rng)
        .expect("we should be able to handle message ID fetch");
    assert_eq!(empty_fetch_response.count, MESSAGE_ID_FETCH_SIZE);
    assert_eq!(empty_fetch_response.messages.len(), MESSAGE_ID_FETCH_SIZE);
}
