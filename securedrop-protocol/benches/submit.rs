use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};

use securedrop_protocol::{
    journalist::JournalistClient, keys::FPFKeyPair, messages::core::SourceJournalistKeyResponse,
    server::Server, source::SourceClient,
};

fn setup_test_environment() -> (SourceClient, Vec<SourceJournalistKeyResponse>) {
    // 1. Create server with newsroom and journalist
    let mut server = Server::new();

    // 2. Setup newsroom
    let newsroom_setup_request = server
        .create_newsroom_setup_request(StdRng::seed_from_u64(666))
        .expect("Can create newsroom setup request");

    // Store the newsroom verifying key before moving the request
    let newsroom_verifying_key = newsroom_setup_request.newsroom_verifying_key;

    // Simulate FPF signing
    let fpf_keypair = FPFKeyPair::new(StdRng::seed_from_u64(666));
    let newsroom_setup_response = newsroom_setup_request
        .sign(&fpf_keypair)
        .expect("Can sign newsroom setup request");

    server.set_fpf_signature(newsroom_setup_response.sig);

    // 3. Setup journalist
    let mut journalist = JournalistClient::new();
    let journalist_setup_request = journalist
        .create_setup_request(StdRng::seed_from_u64(666))
        .expect("Can create journalist setup request");

    server
        .setup_journalist(journalist_setup_request)
        .expect("Can setup journalist");

    // 4. Journalist provides ephemeral keys
    let ephemeral_key_request = journalist
        .create_ephemeral_key_request(StdRng::seed_from_u64(666))
        .expect("Can create ephemeral key request");

    server
        .handle_ephemeral_key_request(ephemeral_key_request)
        .expect("Can handle ephemeral key request");

    // 5. Generate source session from passphrase
    let mut source = SourceClient::from_passphrase(&[1u8; 32]);

    // 6. Source fetches newsroom keys
    let newsroom_key_request = source.fetch_newsroom_keys();
    let newsroom_key_response = server.handle_source_newsroom_key_request(newsroom_key_request);

    // Source handles and verifies the newsroom key response
    source
        .handle_newsroom_key_response(&newsroom_key_response, &fpf_keypair.vk)
        .expect("Newsroom key response should be valid");

    // 7. Source fetches journalist keys
    let journalist_key_request = source.fetch_journalist_keys();
    let journalist_key_responses = server.handle_source_journalist_key_request(
        journalist_key_request,
        &mut StdRng::seed_from_u64(666),
    );

    // Source handles and verifies the journalist key response
    source
        .handle_journalist_key_response(&journalist_key_responses[0], &newsroom_verifying_key)
        .expect("Journalist key response should be valid");

    (source, journalist_key_responses)
}

pub fn bench_submit_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("submit_message");
    let n = 1; // I reduced this for faster benchmarking, we still use a group consisting of 100 measurements

    for index in 0..n {
        group.bench_with_input(
            BenchmarkId::new("submit", format!("message_{}", index)),
            &index,
            |b, _| {
                b.iter(|| {
                    let (source, journalist_key_responses) = setup_test_environment();

                    let test_message = vec![0u8; 512]; // Test message content
                    let mut rng = StdRng::seed_from_u64(666);
                    source
                        .submit_message(test_message, &journalist_key_responses, &mut rng)
                        .expect("Message submission should succeed");
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_submit_message);
criterion_main!(benches);
