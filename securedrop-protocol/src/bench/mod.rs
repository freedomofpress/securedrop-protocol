pub mod encrypt_decrypt;
pub mod submit;

// Re-export functions so they can be called as `bench::bench_*`
pub use encrypt_decrypt::{bench_decrypt, bench_encrypt, bench_fetch};
pub use submit::bench_submit_message;
