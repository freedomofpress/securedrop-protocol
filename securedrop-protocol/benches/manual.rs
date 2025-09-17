use std::env;
use std::time::{Duration, Instant};

// Pull in your wasm-bindgen wrappers' backing functions via the module.
use securedrop_protocol::bench::{bench_decrypt, bench_encrypt, bench_fetch, bench_submit_message};

fn main() {
    // Usage: cargo bench --bench manual -- <which> -n <iterations> [-k num_keybundles]
    // Examples:
    //   cargo bench --bench manual -- submit -n 1000
    //   cargo bench --bench manual -- encrypt -n 500
    //   cargo bench --bench manual -- decrypt -n 200 [-k 15]
    //   cargo bench --bench manual -- fetch -n 50

    let mut which: Option<String> = None;
    let mut iterations: usize = 1000; // default
    let mut num_keybundles: usize = 1; // default number keybundles per journalist

    let mut args = env::args().skip(1); // skip program name
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Cargo may pass this even with harness=false; ignore it.
            "--bench" => continue,

            // Your bench options:
            "-n" | "--iterations" => {
                let v = args.next().unwrap_or_else(|| {
                    eprintln!("Missing value for {arg}");
                    help_and_exit()
                });
                iterations = v.parse().unwrap_or_else(|_| {
                    eprintln!("Invalid number for iterations: {v}");
                    help_and_exit()
                });
            }

            // number of one-time keys per Journalist (affects bench_decrypt)
            "-k" | "--num-onetimekeys" => {
                let v = args.next().unwrap_or_else(|| {
                    eprintln!("If passing {arg}, specify a number");
                    help_and_exit()
                });
                num_keybundles = v.parse().unwrap_or_else(|_| {
                    eprintln!("Invalid number for num-onetimekeys: {v}");
                    help_and_exit()
                });
            }

            // Subcommand (the actual benchmark to run)
            "submit" | "encrypt" | "decrypt" | "fetch" => {
                if which.is_none() {
                    which = Some(arg);
                } else {
                    // If more than one non-flag is supplied, that's ambiguous.
                    eprintln!("Unexpected extra argument: {arg}");
                    help_and_exit();
                }
            }

            // Silently ignore any other cargo-injected or unknown flags (e.g., -Zfoo)
            _ if arg.starts_with('-') => continue,

            // Anything else is not recognized
            _ => {
                eprintln!("Unknown argument: {arg}");
                help_and_exit();
            }
        }
    }

    let which = which.unwrap_or_else(|| help_and_exit());

    // pick the function
    let run = match which.as_str() {
        "submit" => bench_submit_message as fn(usize, usize),
        "encrypt" => bench_encrypt as fn(usize, usize),
        "decrypt" => bench_decrypt as fn(usize, usize),
        "fetch" => bench_fetch as fn(usize, usize),
        _ => {
            eprintln!("Unknown bench: {which}");
            help_and_exit();
        }
    };

    // time it
    let start = Instant::now();
    run(iterations, num_keybundles);
    let total = start.elapsed();

    // print total + average
    let avg = div_duration(total, iterations as u32);
    println!("bench: {which}");
    println!("iterations: {iterations}");
    println!("keybundles/journo (trial decrypt): {num_keybundles}");
    println!("total: {} ms", to_millis(total));
    println!("avg:   {} µs/iter", to_micros(avg));
}

fn help_and_exit() -> ! {
    eprintln!(
        "Usage: cargo bench --bench manual -- <submit|encrypt|decrypt|fetch> [-n <iterations>] [-k <num one-time journalist keybundles> ]\n\
         Default iterations: 1000\n\
         Examples:\n  \
         cargo bench --bench manual -- submit -n 1000\n  \
         cargo bench --bench manual -- encrypt -n 500\n  \
         cargo bench --bench manual -- decrypt -n 200 -k 20 \n  \
         cargo bench --bench manual -- fetch -n 50\n   \
         \n    \
         Note: -k only affects decrypt function"
    );
    std::process::exit(1);
}

fn div_duration(d: Duration, by: u32) -> Duration {
    if by == 0 {
        return Duration::from_nanos(0);
    }
    // Convert to nanoseconds as f64 for precise division, then back.
    let nanos = d.as_secs_f64() * 1e9;
    let each = nanos / (by as f64);
    Duration::from_nanos(each.max(0.0) as u64)
}

fn to_millis(d: Duration) -> String {
    // Keep a few decimals for readability
    format!("{:.3}", d.as_secs_f64() * 1_000.0)
}

fn to_micros(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64() * 1_000_000.0)
}
