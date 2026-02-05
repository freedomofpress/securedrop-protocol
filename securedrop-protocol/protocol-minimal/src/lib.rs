#![no_std]
extern crate alloc;

pub mod api;
pub mod keys;
pub mod messages;
pub mod primitives;
pub mod server;
pub mod setup;
pub mod types;

// Primitives for signing
pub mod sign;
pub use sign::{SelfSignature, Signature, SigningKey, VerifyingKey};

pub mod storage;

pub mod encrypt_decrypt;
