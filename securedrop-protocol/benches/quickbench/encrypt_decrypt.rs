use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use securedrop_protocol::sd_protocol_quickbench;

// This benches src-bin/sd_protocol_quickbench.rs
pub fn setup() -> (Source, Journalist, Vec<u8>, Envelope) {
    let source = Source::new(&mut StdRng::seed_from_u64(666));
    let journalist = Journalist::new(&mut StdRng::seed_from_u64(666));
    let plaintext = b"super secret msg".to_vec();
    let envelope = encrypt(
        &mut StdRng::seed_from_u64(666),
        &source,
        &plaintext,
        &journalist,
    );
    (source, journalist, plaintext, envelope)
}

pub fn bench_encrypt(c: &mut Criterion) {
    let (source, journalist, plaintext, _) = setup();

    c.benchmark_group("encrypt").bench_function(
        BenchmarkId::new("source_to_journalist", ""),
        |b| {
            b.iter(|| {
                encrypt(
                    &mut StdRng::seed_from_u64(666),
                    &source,
                    &plaintext,
                    &journalist,
                )
            });
        },
    );
}

pub fn bench_decrypt(c: &mut Criterion) {
    let (source, journalist, _, envelope) = setup();

    c.benchmark_group("decrypt").bench_function(
        BenchmarkId::new("journalist_from_source", ""),
        |b| {
            b.iter(|| decrypt(&journalist, &envelope));
        },
    );
}

pub fn bench_fetch(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(8888);
    let journalist = Journalist::new(&mut rng);
    let source = Source::new(&mut rng);

    // Generate multiple envelopes and populate a server store
    let mut store = Vec::new();
    for i in 0..100 {
        let envelope = encrypt(
            &mut rng,
            &source,
            format!("msg {i}").as_bytes(),
            &journalist,
        );
        let message_id = [i as u8; LEN_MESSAGE_ID]; // Dummy message IDs for benchmarking

        store.push(ServerMessageStore {
            message_id,
            envelope: envelope,
        });
    }

    let total_responses = 150;

    c.benchmark_group("fetch").bench_function(
        BenchmarkId::new("compute_and_solve", "100_entries"),
        |b| {
            b.iter(|| {
                let challenges = compute_fetch_challenges(&mut rng, &store, total_responses);
                let _solved = solve_fetch_challenges(&journalist, challenges);
            });
        },
    );
}


criterion_group!(benches, bench_encrypt, bench_decrypt, bench_fetch);

criterion_main!(benches);
