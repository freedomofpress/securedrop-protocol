// //! Tests for the core steps of the protocol.
// //! These correspond to steps 5-10 of the spec.

// mod common;

// use securedrop_protocol_minimal::wire::core::WelcomeBundleRequest;
// use securedrop_protocol_minimal::wire::setup::{
//     JournalistEphemeralKeyRequest, JournalistSetupRequest,
// };

// use common::utils::{get_rng, setup_server};
// use common::mocks::{MockApp, MockJournalistApp, Server};

// use std::char::MAX;

// use getrandom;
// use rand_chacha::ChaCha20Rng;
// use rand_core::SeedableRng;

// use securedrop_protocol_minimal::api::{Api, ApplicationContract, ClientProtocol, DefaultProtocol, JournalistApi, JournalistApplicationContract, ServerContract, Untrusted};
// use securedrop_protocol_minimal::challenge::MAX_MESSAGES;
// use securedrop_protocol_minimal::keys::{FPFKeyPair, NewsroomKeyPair};

// use securedrop_protocol_minimal::{
//     Enrollable, Journalist, JournalistPublic, Source, UserPublic, UserSecret, VerifyingKey,
// };

// // TODO: better way (eg parameterize as in benchmarks)
// pub const DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST: usize = 3;

// // Canonical BIP39 test vector: 16 zero bytes of entropy.
// const TEST_MNEMONIC: &str =
//     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// fn mock_app_source(vk: VerifyingKey, mock_backend: &mut Server) -> MockApp {
//     MockApp::new(vk, get_rng(), mock_backend)
// }

// fn mock_app_journalist(vk: VerifyingKey, mock_backend: &mut Server) -> MockJournalistApp {
//     MockJournalistApp(MockApp::new(vk, get_rng(), mock_backend))
// }

// /// Step 5: Source fetches keys and verifies their authenticity
// #[test]
// fn protocol_step_5_source_fetch_keys() {
//     let mut rng = get_rng();
//     let fpf_keys = FPFKeyPair::new(&mut get_rng()).expect("FPF key generation failed");

//     // Setup: Create server with newsroom and journalist
//     let (mut server_session, nr_key, nr_sig) = setup_server(rng, &fpf_keys);

//     // Setup newsroom
//     let newsroom_setup_request = server_session
//         .create_newsroom_setup_request()
//         .expect("Can create newsroom setup request");

//     // Store the newsroom verifying key for verification
//     let newsroom_verifying_key = newsroom_setup_request.newsroom_verifying_key;

//     // Simulate FPF signing (in real implementation, this would be done by FPF)
//     let newsroom_setup_response = newsroom_setup_request
//         .sign(&fpf_keys)
//         .expect("Can sign newsroom setup request");

//     // Store the FPF signature in the server session for later use
//     server_session.set_fpf_signature(newsroom_setup_response.sig);

//     // setup journalist (new)
//     let journalist = Journalist::new(&mut get_rng(), DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST);
//     let enrollment = journalist.enroll();

//     // set up application
//     let mock_app_journalist = mock_app_journalist(nr_key.clone(), &mut server_session);

//     // the mock app directly forward requests to the server and returns the result
//     let journalist_setup_request = mock_app_journalist
//         .create_setup_request(JournalistSetupRequest { enrollment })
//         .expect("Journalist can enroll");

//     // Journalist provides ephemeral keys
//     let req = JournalistEphemeralKeyRequest {
//         bundles: journalist.signed_keybundles(),
//         verifying_key: journalist.signing_key().clone(),
//     };

//     assert_eq!(
//         req.bundles.len(),
//         DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST
//     );

//     let ephemeral_key_result = mock_app_journalist
//         .create_ephemeral_key_request(req)
//         .expect("Journalist can submit ephemeral keys");

//     // Step 4: Generate source session from passphrase
//     let mut source = Source::from_passphrase(TEST_MNEMONIC).expect("valid test mnemonic");
//     let mut mock_app_source = mock_app_source(nr_key.clone(), &mut server_session);

//     // Step 5: Source fetches the welcome bundle and verifies it.
//     let welcome = mock_app_source
//         .request_keys(WelcomeBundleRequest {})
//         .expect("Can retrieve welcome bundle");

//     // We only have one journalist rn
//     assert_eq!(welcome.journalists.len(), 1);

//     // Source fetches one ephemeral bundle per journalist (consuming) and
//     // assembles the journalist's public view.
//     let ephemeral = server_session.handle_journalist_ephemeral_keys(&mut get_rng());
//     assert_eq!(ephemeral.len(), 1);
//     let journalist_views = MockApp::<'_>::verify_ephemeral(&welcome.journalists, &ephemeral)
//         .expect("Journalist ephemeral keys should be valid");
//     assert_eq!(journalist_views.len(), 1);
//     let journalist_view = &journalist_views[0];

//     // Verify the journalist's signing key matches our expectation
//     // (todo improve this)
//     let journalist_public = &journalist.public(0);

//     let &jvk = journalist_public.verifying_key();

//     assert_eq!(
//         journalist_view.verifying_key().into_bytes(),
//         jvk.into_bytes()
//     );

//     // Verify the journalist's fetch key matches our expectation
//     assert_eq!(
//         journalist_view.fetch_pk().clone().into_bytes(),
//         journalist.fetch_keypair().1.clone().into_bytes()
//     );

//     // Verify the journalist's message (APKE) key matches our expectation
//     assert_eq!(
//         journalist_view.message_auth_pk().as_bytes(),
//         journalist.message_auth_keypair().public_key().as_bytes()
//     );

//     // Verify that ephemeral keys were consumed (deleted from server storage)
//     // After fetching, the journalist should have no ephemeral keys left
//     let journalist_id = &mut server_session
//         .find_journalist_id(&jvk)
//         .expect("Journalist should be found");
//     assert_eq!(
//         server_session.ephemeral_keys_count(journalist_id.clone()),
//         DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST - 1
//     );

//     // Consume the remaining keys
//     for _i in 0..DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST - 1 {
//         let _ = server_session.handle_journalist_ephemeral_keys(&mut rng);
//     }
//     assert!(!server_session.has_ephemeral_keys(journalist_id.clone()));

//     // Test that subsequent requests return no keys (since they were consumed)
//     let empty_responses = server_session.handle_journalist_ephemeral_keys(&mut get_rng());
//     assert_eq!(empty_responses.len(), 0);

//     // Test that invalid FPF signatures are rejected
//     let wrong_fpf_keypair = FPFKeyPair::new(&mut get_rng()).expect("FPF key generation failed");

//     // Test that invalid newsroom signatures on journalist keys are rejected
//     let wrong_newsroom_keypair =
//         NewsroomKeyPair::new(&mut get_rng()).expect("Newsroom key generation failed");
//     assert!(
//     mock_app_source.verify_long_term(&welcome.journalists, &wrong_newsroom_keypair.verifying_key())
//             .is_err()
//     );

//     assert!(
//         mock_app_source
//             .handle_welcome(&welcome, &wrong_fpf_keypair.verifying_key())
//             .is_err()
//     );

// }

// /// Sets up a newsroom with `num_journalists` enrolled journalists, each of
// /// whom has uploaded their ephemeral key bundles.
// fn setup_newsroom_with_journalists(
//     rng: &mut ChaCha20Rng,
//     num_journalists: usize,
// ) -> (Server, FPFKeyPair, Vec<Journalist>) {
//     let fpf_keypair = FPFKeyPair::new(rng).expect("FPF key generation failed");

//     let (mut server_session, nr, _) = setup_server(get_rng(), &fpf_keypair);
//     let journalist_client_app = mock_app_journalist(nr, &mut server_session);

//     let mut journalists = Vec::with_capacity(num_journalists);
//     for _ in 0..num_journalists {
//         let journalist = Journalist::new(rng, DEFAULT_NUM_EPHEMERAL_KEYBUNDLES_JOURNALIST);
//         let req= journalist_client_app.prepare_enrollment(&journalist).expect("Journalist can generate enrollment package");
//         journalist_client_app.create_setup_request(req).expect("Journalist can enroll on server");

//         let kb_req = journalist_client_app.prepare_keybundles(&journalist).expect("Journalist can prepare short-lived key bundles");
//         journalist_client_app.create_ephemeral_key_request(kb_req).expect("Journalist can upload short-lived keybundles to server");

//         journalists.push(journalist);
//     }

//     (server_session, fpf_keypair, journalists)
// }

// /// Step 5 with multiple journalists: the source gets one public view per
// /// enrolled journalist.
// #[test]
// fn protocol_step_5_source_fetch_keys_multiple_journalists() {
//     let mut rng = get_rng();
//     let (mut server_session, fpf_keypair, journalists) =
//         setup_newsroom_with_journalists(&mut rng, 3);

//     let nr_key = server_session.newsroom_verifying_key().expect("server setup complete");

//     let mut source_keys = Source::from_passphrase(TEST_MNEMONIC).expect("valid test mnemonic");

//     let source_app = mock_app_source(nr_key, &mut server_session);
//     let welcome = source_app.request_keys(WelcomeBundleRequest {  }).expect("Source can fetch welcome package");

//     assert_eq!(welcome.journalists.len(), 3);

//     let ephemeral = server_session.handle_journalist_ephemeral_keys(&mut rng);
//     assert_eq!(ephemeral.len(), 3);
//     let views = MockApp::<'_>::verify_ephemeral(&welcome.journalists, &ephemeral)
//         .expect("Journalist ephemeral keys should be valid");
//     assert_eq!(views.len(), 3);

//     // Every enrolled journalist appears exactly once
//     for journalist in &journalists {
//         let jvk = journalist.public(0).verifying_key().into_bytes();
//         assert_eq!(
//             views
//                 .iter()
//                 .filter(|v| v.verifying_key().into_bytes() == jvk)
//                 .count(),
//             1
//         );
//     }
// }

// /// Regression test for #166: serve two valid bundles for the same journalist, so that the source would send them the same message twice. Source MUST reject.
// #[test]
// fn protocol_step_5_source_rejects_duplicate_journalist_bundles() {
//     let mut rng = get_rng();
//     let (mut server_session, fpf_keypair, _journalists) =
//         setup_newsroom_with_journalists(&mut rng, 1);

//     let nr_key = server_session.newsroom_verifying_key().expect("Server setup successful");

//     let mut source = Source::from_passphrase(TEST_MNEMONIC).expect("valid test mnemonic");

//     let mut source_app = mock_app_source(nr_key, &mut server_session);
//     let welcome = source_app.request_keys(WelcomeBundleRequest {  }).expect("Can fetch welcome bundle");
//     source_app.handle_welcome(&welcome, &fpf_keypair.verifying_key()).expect("Valid welcome bundle");

//     // Get two different bundles for the same journalist
//     let mut ephemeral = server_session.handle_journalist_ephemeral_keys(&mut rng);
//     ephemeral.extend(server_session.handle_journalist_ephemeral_keys(&mut rng));
//     assert_eq!(ephemeral.len(), 2);
//     assert_eq!(ephemeral[0].vk.into_bytes(), ephemeral[1].vk.into_bytes());
//     assert_ne!(
//         ephemeral[0].ephemeral.0.as_bytes(),
//         ephemeral[1].ephemeral.0.as_bytes()
//     );

//     assert!(
//         MockApp::<'_>::verify_ephemeral(&welcome.journalists, &ephemeral)
//             .is_err()
//     );
// }

// /// Step 6: Source submits a message
// #[test]
// fn protocol_step_6_source_submits_message() {
//     let mut rng = get_rng();
//     let fpf_keypair = FPFKeyPair::new(&mut rng).expect("FPF key generation failed");

//     // Setup: Complete steps 1-5 (reuse from previous test)
//     let (mut server_session, nr_key, sig) = setup_server(get_rng(), &fpf_keypair);

//     // Setup journalist
//     let mut journalist = Journalist::new(&mut rng, 10);

//     let mock_journalist_app = mock_app_journalist(nr_key.clone(), &mut server_session);
//     let enroll = journalist.enroll();

//     mock_journalist_app
//         .create_setup_request(JournalistSetupRequest { enrollment: enroll })
//         .expect("Can enroll journalist");
//     // Journalist provides ephemeral keys
//     let journalist_kb_req = mock_journalist_app.prepare_keybundles(&journalist).expect("can prepare ephemeral keybundles");
//     let ephemeral_key_request = mock_journalist_app.create_ephemeral_key_request(journalist_kb_req).expect("can upload ephemeral key bundles");

//     // Source setup
//     // let source = Source::from_passphrase(&[1u8; 32]);
//     let mut source = Source::new(&mut rng);
//     let source_client = mock_app_source(nr_key, &mut server_session);

//     // Source fetches keys (Step 5)
//     let welcome = source_client.request_keys(WelcomeBundleRequest {  }).expect("Can fetch welcome");
//     source_client
//         .handle_welcome(&welcome, &fpf_keypair.verifying_key())
//         .expect("Welcome bundle should be valid");

//     let ephemeral = server_session.handle_journalist_ephemeral_keys(&mut rng);
//     let journalist_publics = MockApp::<'_>::verify_ephemeral(&welcome.journalists, &ephemeral)
//         .expect("Journalist ephemeral keys should be valid");
//     assert_eq!(journalist_publics.len(), 1);

//     // Step 6: Source submits a message
//     let message_content = b"Hello, this is a test message!";
//     let message = source_client.send_message(Untrusted(message_content), &source, &journalist_publics[0])
//         .expect("Can submit message");

//     // Verify that the message was stored. todo: server wont return message_id
//     //assert!(server_session.has_message(&message_id));
// }

// /// Step 7: Privacy-preserving message ID fetch
// #[test]
// fn protocol_step_7_message_id_fetch() {
//     let mut rng = get_rng();

//     let fpf_keys = FPFKeyPair::new(&mut get_rng()).expect("can create fpf keys");

//     // Setup: Complete steps 1-6 (reuse from previous test)
//     let (mut server_session, nr_key, signature_on_nr_key) = setup_server(get_rng(), &fpf_keys);

//     let newsroom_setup_response = newsroom_setup_request
//         .sign(&fpf_keypair)
//         .expect("Can sign newsroom setup request");

//     server_session.set_fpf_signature(newsroom_setup_response.sig);

//     // Setup journalist : TODO keybundles
//     let mut journalist = Journalist::new(&mut rng, 10);
//     // let mut journalist_session = JournalistClient::new(
//     //     journalist,
//     //     newsroom_verifying_key,
//     //     newsroom_setup_response.sig,
//     // );
//     let journalist_setup_request = journalist
//         .create_setup_request()
//         .expect("Can create journalist setup request");

//     // Store the newsroom verifying key in the journalist session
//     journalist.set_newsroom_verifying_key(newsroom_verifying_key);

//     // Journalist provides ephemeral keys
//     let ephemeral_key_request = journalist.create_ephemeral_key_request();

//     server_session
//         .handle_ephemeral_key_request(ephemeral_key_request)
//         .expect("Can handle ephemeral key request");

//     // Source setup
//     let mut source = Source::from_passphrase(TEST_MNEMONIC).expect("valid test mnemonic");

//     // Source fetches keys (Step 5)
//     let welcome = server_session.handle_welcome();
//     source
//         .handle_welcome(&welcome, &fpf_keypair.verifying_key())
//         .expect("Welcome bundle should be valid");

//     let ephemeral = server_session.handle_journalist_ephemeral_keys(&mut rng);
//     let journalist_publics = source
//         .verify_ephemeral_keys(&welcome.journalists, &ephemeral)
//         .expect("Journalist ephemeral keys should be valid");
//     assert_eq!(journalist_publics.len(), 1);

//     // Submit a message (Step 6)
//     let message_content = b"Hello, this is a test message!";
//     let message = source
//         .encrypt_message(&mut rng, message_content, &source, &journalist_publics[0])
//         .expect("Can submit message");

//     let message_id = server_session
//         .handle_message_submit(message.clone(), &mut rng)
//         .expect("Can handle message submission");

//     // Step 7: Test message ID fetch from journalist perspective
//     let journalist_fetch_request = journalist.fetch_message_ids(&mut rng);
//     let journalist_fetch_response = server_session
//         .handle_request_challenges(journalist_fetch_request, &mut rng)
//         .expect("should be able to fetch message IDs");

//     // Verify response structure
//     assert_eq!(journalist_fetch_response.count, MAX_MESSAGES);
//     assert_eq!(journalist_fetch_response.messages.len(), MAX_MESSAGES);

//     // Process the response to extract message IDs
//     let journalist_message_ids = journalist
//         .solve_fetch_challenges(&journalist_fetch_response.messages)
//         .expect("Can process message ID response");

//     // Verify that the journalist can also find the message ID
//     assert!(
//         journalist_message_ids.contains(&message_id),
//         "Journalist should find the message ID"
//     );

//     // Verify privacy properties: response size is always the same
//     let empty_fetch_request = source.fetch_message_ids(&mut rng);
//     let empty_fetch_response = server_session
//         .handle_request_challenges(empty_fetch_request, &mut rng)
//         .expect("we should be able to handle message ID fetch");
//     assert_eq!(empty_fetch_response.count, MAX_MESSAGES);
//     assert_eq!(empty_fetch_response.messages.len(), MAX_MESSAGES);
// }
