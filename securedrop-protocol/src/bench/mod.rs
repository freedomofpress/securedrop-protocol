pub mod submit;
pub mod encrypt_decrypt;

// Re-export functions so they can be called as `bench::bench_*`
pub use submit::bench_submit_message;
pub use encrypt_decrypt::{bench_encrypt, bench_decrypt, bench_fetch};