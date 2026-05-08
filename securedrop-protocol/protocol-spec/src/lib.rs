//! Hacspec-style specification of the SecureDrop Protocol.
//!
//! Mirrors `docs/protocol.md` v0.4. This proof-of-concept currently
//! contains only §SD-PKE (lines 304-333 of the doc).
//!
//! The implementation crate `securedrop-protocol-minimal` is intended to
//! be shown to refine this spec via hax + F*. See
//! `proofs/SecureDrop.SdPke.Refinement.fst` for the lemma sketch.

#![no_std]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

pub const PROTOCOL_VERSION: &str = "0.4";

pub mod primitives;
pub mod sd_pke;
