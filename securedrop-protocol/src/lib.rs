#![no_std]

//! A draft implementation of the SecureDrop protocol.
//!
//! WARNING: This was implemented only for benchmarking and research purposes
//! and is not ready for production use.

extern crate alloc;

/// The keys used in the SecureDrop protocol.
pub mod keys;

/// Common client functionality.
pub mod client;
pub use client::Client;

/// Protocol messages used in the setup and core messaging protocol.
pub mod messages;

/// Server-side protocol implementation.
pub mod server;

/// Source-side protocol implementation.
pub mod source;

/// Journalist-side protocol implementation.
pub mod journalist;

/// Setup steps in the protocol.
pub mod setup;

/// Primitives for DH, PPK.
pub mod primitives;

/// Primitives for signing.
///
/// TODO: Move to primitives?
pub mod sign;

pub use sign::{SelfSignature, Signature, SigningKey, VerifyingKey};

/// Server storage
pub mod storage;

pub mod bench;

use wasm_bindgen::prelude::*;

// For now we don't use the u32 param here, but when we update
// the submit benchmark we can add parameterized keybundle size
// as we have in the other benches.
#[wasm_bindgen]
pub fn bench_submit_message(iterations: u32, unused: u32) {
    bench::bench_submit_message(iterations as usize, unused as usize);
}

#[wasm_bindgen]
pub fn bench_encrypt(iterations: u32, num_keybundles: u32) {
    bench::bench_encrypt(iterations as usize, num_keybundles as usize);
}

#[wasm_bindgen]
pub fn bench_decrypt(iterations: u32, num_keybundles: u32) {
    bench::bench_decrypt(iterations as usize, num_keybundles as usize);
}

#[wasm_bindgen]
pub fn bench_fetch(iterations: u32, num_keybundles: u32) {
    bench::bench_fetch(iterations as usize, num_keybundles as usize);
}
