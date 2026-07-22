//! Benchmark for the server fetch challenge computation
//!
//! `cargo bench -p securedrop-protocol-minimal --bench challenges`

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use securedrop_protocol_minimal::encrypt_decrypt::{compute_fetch_challenges, encrypt};
use securedrop_protocol_minimal::{Envelope, Journalist, Source, UserSecret};

const STORE_SIZES: &[usize] = &[100, 500, 1000, 2000, 5000, 10000];

/// Number of journalist keybundles that stored messages are spread across
const KEYBUNDLES: usize = 8;

fn build_store(n: usize) -> Vec<([u8; 16], Envelope)> {
    let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());
    let journalist = Journalist::new(&mut rng, KEYBUNDLES);
    let source = Source::new(&mut rng);

    let mut store = Vec::with_capacity(n);
    for j in 0..n {
        let pt = source.build_message(format!("benchmark message {j}").into_bytes());
        let env = encrypt(&mut rng, &source, &pt, &journalist.public(j % KEYBUNDLES));

        let mut message_id = [0u8; 16];
        message_id[..8].copy_from_slice(&(j as u64).to_le_bytes());
        store.push((message_id, env));
    }
    store
}

fn bench_compute_fetch_challenges(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_fetch_challenges");

    for &size in STORE_SIZES {
        let store = build_store(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &store, |b, store| {
            let mut rng = ChaCha20Rng::from_rng(&mut rand::rng());
            b.iter(|| compute_fetch_challenges(&mut rng, black_box(store), black_box(store.len())));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_compute_fetch_challenges);
criterion_main!(benches);
