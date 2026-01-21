use std::env;
use std::time::{Duration, Instant};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Serialize;

use securedrop_protocol_minimal::bench::encrypt_decrypt::{
    Envelope, FetchResponse, Journalist, Plaintext, ServerMessageStore, Source, User,
    compute_fetch_challenges,
};

use securedrop_protocol_bench::{bench_decrypt, bench_encrypt, bench_fetch};

#[derive(Clone, Copy, PartialEq, Eq)]
enum RawFmt {
    None,
    Json,
    Csv,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    bench: &'a str,
    iterations: usize,
    keybundles: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenges: Option<usize>,

    total_ms: f64,
    avg_ms: f64,
    min_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    p99_ms: f64,
    max_ms: f64,

    samples_ms: Vec<f64>,
}

fn main() {
    // Usage:
    //   cargo bench --bench manual -- all     -n 10  -k 500 -j 3000 [--raw json|csv] [--quiet]
    //   cargo bench --bench manual -- encrypt -n 500 [--include-rng] [--raw json|csv] [--quiet]
    //   cargo bench --bench manual -- decrypt -n 500 -k 20 [--raw json|csv] [--quiet]
    //   cargo bench --bench manual -- fetch   -n 200 -k 20 -j 150 [--raw json|csv] [--quiet]

    let mut which: Option<String> = None;
    let mut iterations: usize = 10;
    let mut keybundles: usize = 500;
    let mut challenges: usize = 10000;
    let mut raw_fmt = RawFmt::None;
    let mut quiet = false;
    let mut include_rng = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bench" => continue,
            "-n" | "--iterations" => {
                iterations = parse_usize(&next_val(&mut args, &arg), "iterations")
            }
            "-k" | "--num-onetimekeys" => {
                keybundles = parse_usize(&next_val(&mut args, &arg), "num-onetimekeys")
            }
            "-j" | "--challenges" => {
                challenges = parse_usize(&next_val(&mut args, &arg), "challenges")
            }
            "--raw" => {
                let v = next_val(&mut args, &arg);
                raw_fmt = match v.as_str() {
                    "json" => RawFmt::Json,
                    "csv" => RawFmt::Csv,
                    _ => die(&format!("--raw expects 'json' or 'csv', got {v}")),
                }
            }
            "--quiet" => quiet = true,
            "--include-rng" => include_rng = false,
            "encrypt" | "decrypt" | "fetch" | "all" => {
                if which.is_none() {
                    which = Some(arg);
                } else {
                    die(&format!("Unexpected extra argument: {arg}"));
                }
            }
            _ if arg.starts_with('-') => continue,
            _ => die(&format!("Unknown argument: {arg}")),
        }
    }

    let which = which.unwrap_or_else(|| help_and_exit());

    match which.as_str() {
        "encrypt" => {
            let samples = bench_encrypt_loop(iterations, keybundles, include_rng);
            output(
                "encrypt", iterations, keybundles, None, &samples, raw_fmt, quiet,
            );
        }
        "decrypt" => {
            let samples = bench_decrypt_loop(iterations, keybundles);
            output(
                "decrypt", iterations, keybundles, None, &samples, raw_fmt, quiet,
            );
        }
        "fetch" => {
            let samples = bench_fetch_loop(iterations, keybundles, challenges);
            output(
                "fetch",
                iterations,
                keybundles,
                Some(challenges),
                &samples,
                raw_fmt,
                quiet,
            );
        }
        "all" => {
            let e = bench_encrypt_loop(iterations, keybundles, include_rng);
            output("encrypt", iterations, keybundles, None, &e, raw_fmt, quiet);
            let d = bench_decrypt_loop(iterations, keybundles);
            output("decrypt", iterations, keybundles, None, &d, raw_fmt, quiet);
            let f = bench_fetch_loop(iterations, keybundles, challenges);
            output(
                "fetch",
                iterations,
                keybundles,
                Some(challenges),
                &f,
                raw_fmt,
                quiet,
            );
        }
        _ => die(&format!("Unknown bench: {which}")),
    }
}

// -------------------- encrypt --------------------

fn bench_encrypt_loop(iterations: usize, keybundles: usize, include_rng: bool) -> Vec<Duration> {
    let mut durations = Vec::with_capacity(iterations);
    let mut sink = 0usize;

    for _ in 0..iterations {
        let mut prep_rng = mk_rng();
        let sender = Source::new(&mut prep_rng);
        let recipient = Journalist::new(&mut prep_rng, keybundles);
        let msg = b"super secret msg".to_vec();

        let plaintext = Plaintext {
            sender_fetch_key: *sender.get_fetch_pk(),
            sender_reply_pubkey_hybrid: sender.keys.hybrid_md_pk,
            sender_reply_pubkey_pq_psk: sender.keys.pq_kem_psk_pk,
            msg: msg,
        };

        // Bundle index chosen outside the timed section
        let bundle_ix = if keybundles == 0 {
            0
        } else {
            (prep_rng.next_u32() as usize) % keybundles
        };

        if include_rng {
            // Time the seed fill + encrypt together
            let t0 = Instant::now();
            let mut seed = [0u8; 32];
            prep_rng.fill_bytes(&mut seed);
            let env: Envelope = bench_encrypt(
                seed,
                &sender as &dyn User,
                &recipient as &dyn User,
                bundle_ix,
                &plaintext.to_bytes(),
            );
            let dt = t0.elapsed();
            durations.push(dt);
            sink ^= env.size_hint();
        } else {
            // Seed fill happens outside the timed section (default)
            let mut seed = [0u8; 32];
            prep_rng.fill_bytes(&mut seed);

            let t0 = Instant::now();
            let env: Envelope = bench_encrypt(
                seed,
                &sender as &dyn User,
                &recipient as &dyn User,
                bundle_ix,
                &plaintext.to_bytes(),
            );
            let dt = t0.elapsed();
            durations.push(dt);
            sink ^= env.size_hint();
        }
    }

    std::hint::black_box(sink);
    durations
}

// -------------------- decrypt --------------------

fn bench_decrypt_loop(iterations: usize, keybundles: usize) -> Vec<Duration> {
    let mut durations = Vec::with_capacity(iterations);
    let mut sink = 0usize;

    for _ in 0..iterations {
        let mut prep_rng = mk_rng();
        let sender = Source::new(&mut prep_rng);
        let recipient = Journalist::new(&mut prep_rng, keybundles);
        let msg = b"super secret msg".to_vec();

        let pt = Plaintext {
            sender_reply_pubkey_hybrid: sender.keys.hybrid_md_pk,
            sender_fetch_key: *sender.get_fetch_pk(),
            msg: msg,
            sender_reply_pubkey_pq_psk: sender.keys.pq_kem_psk_pk,
        };

        // Prepare envelope (not timed)
        let mut seed = [0u8; 32];
        let bundle_ix = if keybundles == 0 {
            0
        } else {
            (prep_rng.next_u32() as usize) % keybundles
        };
        let env: Envelope = bench_encrypt(
            seed,
            &sender as &dyn User,
            &recipient as &dyn User,
            bundle_ix,
            &pt.to_bytes(),
        );

        // Time ONLY decrypt
        let t0 = Instant::now();
        let pt = bench_decrypt(&recipient, &env);
        let dt = t0.elapsed();
        durations.push(dt);

        sink ^= pt.len();
    }
    std::hint::black_box(sink);
    durations
}

// -------------------- fetch (solver only) --------------------

fn bench_fetch_loop(iterations: usize, keybundles: usize, challenges: usize) -> Vec<Duration> {
    let mut durations = Vec::with_capacity(iterations);
    let mut sink = 0usize;

    for i in 0..iterations {
        let mut prep_rng = mk_rng();
        let journalist = Journalist::new(&mut prep_rng, keybundles);
        let source = Source::new(&mut prep_rng);

        // Build store (prep)
        let store_size = challenges.min(100);
        let mut store: Vec<ServerMessageStore> = Vec::with_capacity(store_size);
        for j in 0..store_size {
            let mut seed = [0u8; 32];
            prep_rng.fill_bytes(&mut seed);
            let bundle_ix = if keybundles == 0 {
                0
            } else {
                (prep_rng.next_u32() as usize) % keybundles
            };

            let pt = Plaintext {
                msg: format!("iter{i}-msg{j}").into(),
                sender_fetch_key: source.keys.dhakem_pk,
                sender_reply_pubkey_hybrid: source.keys.hybrid_md_pk,
                sender_reply_pubkey_pq_psk: source.keys.pq_kem_psk_pk,
            };

            let env = bench_encrypt(
                seed,
                &source as &dyn User,
                &journalist as &dyn User,
                bundle_ix,
                &pt.to_bytes(),
            );
            let mut message_id = [0u8; 16];
            message_id.fill((j & 0xff) as u8);
            store.push(ServerMessageStore::new(message_id, env));
        }

        // Generate challenges (not timed)
        let challenges: Vec<FetchResponse> =
            compute_fetch_challenges(&mut prep_rng, &store, challenges);

        // Time ONLY the solver
        let t0 = Instant::now();
        let ids = bench_fetch(&journalist, challenges);
        let dt = t0.elapsed();
        durations.push(dt);

        sink ^= ids.len();
    }
    std::hint::black_box(sink);
    durations
}

// -------------------- output & stats --------------------

fn output(
    which: &str,
    iterations: usize,
    keybundles: usize,
    challenges: Option<usize>,
    samples: &[Duration],
    raw_fmt: RawFmt,
    quiet: bool,
) {
    match raw_fmt {
        RawFmt::None => {
            if !quiet {
                print_series_report(which, iterations, keybundles, challenges, samples);
            }
        }
        RawFmt::Json => {
            let (total_ms, avg_ms, min_ms, p50, p90, p99, max_ms) = stats_ms(samples);
            let report = JsonReport {
                bench: which,
                iterations,
                keybundles: keybundles,
                challenges,
                total_ms,
                avg_ms,
                min_ms,
                p50_ms: p50,
                p90_ms: p90,
                p99_ms: p99,
                max_ms,
                samples_ms: to_ms(samples),
            };
            println!("{}", serde_json::to_string(&report).unwrap());
        }
        RawFmt::Csv => {
            let ms = to_ms(samples);
            for v in ms {
                println!("{v}");
            }
            if !quiet {
                let (total_ms, avg_ms, min_ms, p50, p90, p99, max_ms) = stats_ms(samples);
                eprintln!(
                    "# bench={which} iterations={iterations} keybundles={keybundles} challenges={:?} total_ms={:.3} avg_ms={:.3} min_ms={:.3} p50_ms={:.3} p90_ms={:.3} p99_ms={:.3} max_ms={:.3}",
                    challenges, total_ms, avg_ms, min_ms, p50, p90, p99, max_ms
                );
            }
        }
    }
}

fn print_series_report(
    which: &str,
    iterations: usize,
    keybundles: usize,
    challenges: Option<usize>,
    samples: &[Duration],
) {
    let (total_ms, avg_ms, min_ms, p50, p90, p99, max_ms) = stats_ms(samples);

    println!("bench: {which}");
    println!("iterations: {iterations}");
    println!("keybundles/journo: {keybundles}");
    if let Some(c) = challenges {
        println!("challenges/iter: {c}");
    }
    println!("total: {:.3} ms", total_ms);
    println!("avg:   {:.3} ms/iter", avg_ms);
    println!(
        "min:   {:.3} ms  p50: {:.3}  p90: {:.3}  p99: {:.3}  max: {:.3} ms",
        min_ms, p50, p90, p99, max_ms
    );
}

fn stats_ms(samples: &[Duration]) -> (f64, f64, f64, f64, f64, f64, f64) {
    let ms = to_ms(samples);
    let total_ms: f64 = ms.iter().sum();
    let avg_ms = if ms.is_empty() {
        0.0
    } else {
        total_ms / ms.len() as f64
    };
    let mut sorted = ms.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let idx = ((q * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
        sorted[idx]
    };
    let min = *sorted.first().unwrap_or(&0.0);
    let max = *sorted.last().unwrap_or(&0.0);
    (
        total_ms,
        avg_ms,
        min,
        pick(0.50),
        pick(0.90),
        pick(0.99),
        max,
    )
}

fn to_ms(samples: &[Duration]) -> Vec<f64> {
    samples.iter().map(|d| d.as_secs_f64() * 1_000.0).collect()
}

// -------------------- helpers --------------------

fn mk_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom failed");
    ChaCha20Rng::from_seed(seed)
}

fn next_val(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next()
        .unwrap_or_else(|| die(&format!("Missing value for {flag}")))
}

fn parse_usize(s: &str, name: &str) -> usize {
    s.parse::<usize>()
        .unwrap_or_else(|_| die(&format!("Invalid number for {name}: {s}")))
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    help_and_exit();
}

fn help_and_exit() -> ! {
    eprintln!(
        "Usage: cargo bench --bench manual -- <encrypt|decrypt|fetch|all> \
         [-n <iterations>] [-k <num one-time journalist keybundles>] [-j <challenges>] \
         [--include-rng] [--raw json|csv] [--quiet]\n\
         Defaults: -n 10, -k 500, -j 3000\n\
         Examples:\n  \
         cargo bench --bench manual -- all -n 50 -k 500 -j 3000\n  \
         cargo bench --bench manual -- encrypt -n 200 --include-rng --raw json --quiet\n  \
         cargo bench --bench manual -- fetch -n 100 -k 50 -j 1000 --raw csv --quiet\n"
    );
    std::process::exit(1);
}
