//! Server-side cryptographic operations.
//!
//! This module is stateless: sessions and storage are the responsibility of
//! the server implementation (see the `demo-server` crate).

pub mod challenge;
pub mod setup;
