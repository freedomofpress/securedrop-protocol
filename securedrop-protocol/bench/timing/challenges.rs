//! Constant-time verification using DudeCT (Dude, is my Code Constant Time?)
//!
//! This benchmark uses statistical testing to verify that cryptographic operations
//! execute in constant time, regardless of secret inputs.
//!
//! DudeCT performs Welch's t-test to detect timing differences between two classes
//! of inputs. A t-statistic > 5 indicates a timing leak with high confidence.
//!
//! Run with: cargo run --release --example challenges
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

use securedrop_protocol_bench::bench_encrypt;
use securedrop_protocol_minimal::{Envelope, Journalist, Source, UserSecret};

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main, rand::RngExt};
use securedrop_protocol_minimal::server::challenge::ChallengeInput;
use securedrop_protocol_minimal::server::challenge::compute_fetch_challenges;

fn mk_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom failed");
    ChaCha20Rng::from_seed(seed)
}

/// Test constant-time compute_fetch_challenges_timing
fn compute_fetch_challenges_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    let num_samples: usize = 50000;

    let challenges: usize = 25;
    let mut prep_rng = mk_rng();
    let source = Source::new(&mut prep_rng);
    let journalist = Journalist::new(&mut prep_rng, 1);

    // Build store (prep)
    let mut store_entries: Vec<ChallengeInput> = Vec::with_capacity(challenges);
    for j in 0..challenges {
        let mut seed = [0u8; 32];
        prep_rng.fill(&mut seed);
        let pt = source.build_message(format!("msg{j}").into());
        let env = bench_encrypt(seed, &source, &journalist.public(0), &pt);
        let mut message_id = [0u8; 16];
        message_id.fill((j & 0xff) as u8);
        store_entries.push(env.to_challenges(message_id));
    }

    for _ in 0..num_samples {
        // Flip a coin to randomly select and run the left (all decoy) or right(some number of real challenges) distributions.
        let (k, class) = if rng.random::<bool>() {
            (0, Class::Left)
        } else {
            (challenges, Class::Right)
        };
        let local_rng = mk_rng();
        runner.run_one(class, || {
            compute_fetch_challenges(&mut local_rng.clone(), &store_entries[..k], challenges);
        });
    }
}

ctbench_main!(compute_fetch_challenges_timing);
