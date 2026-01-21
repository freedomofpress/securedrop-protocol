#![no_std]
extern crate alloc;

mod encrypt_decrypt;

pub use encrypt_decrypt::{bench_decrypt, bench_encrypt, bench_fetch};
