//! Hacspec-style specification of the SecureDrop Protocol.
//!
//! Mirrors `docs/protocol.md` v0.4 section by section. Cryptographic
//! primitives are abstract (see `primitives`); the implementation crate
//! `securedrop-protocol-minimal` is intended to be shown to refine this
//! spec via hax + F*. See `proofs/SecureDrop.SdPke.Refinement.fst` for
//! the SD-PKE lemma sketch.
//!
//! Most function bodies outside `sd_pke` are `unimplemented!()`; the
//! types, signatures, and module layout are the design artifact. SD-PKE
//! is fleshed out as the proof-of-concept refinement target.

#![no_std]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

pub const PROTOCOL_VERSION: &str = "0.4";

pub mod primitives;
pub mod keys;
pub mod setup;
pub mod sd_pke;
pub mod sd_apke;
pub mod messaging;
pub mod wire;
