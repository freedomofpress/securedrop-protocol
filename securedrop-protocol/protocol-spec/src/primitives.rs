//! Abstract cryptographic primitives.
//!
//! Each function here is an opaque boundary: ProVerif treats them as
//! constructors with axiomatized properties; F* uses pre/postconditions
//! for refinement. The implementation crate provides concrete bodies
//! (libcrux, hpke-rs); this crate never inspects them.
//!
//! This proof-of-concept restricts the abstract primitive surface to
//! exactly what §SD-PKE needs (X-Wing keygen + HPKE Base seal/open).

use alloc::vec::Vec;

// ===========================================================================
// X-Wing(X25519, ML-KEM-768) (§Key Hierarchy line 142, §SD-PKE line 309)
// ===========================================================================

/// X-Wing decapsulation key length per the I-D's encoding (§docs/protocol.md
/// line 18 of constants.rs in the impl).
pub const XWING_SK_LEN: usize = 32;
/// X-Wing encapsulation key length (§Wire formats, line 638).
pub const XWING_PK_LEN: usize = 1216;
/// X-Wing encapsulated shared-secret ciphertext length (§Wire formats line 656).
pub const XWING_ENC_LEN: usize = 1120;

pub type XwingSk = [u8; XWING_SK_LEN];
pub type XwingPk = [u8; XWING_PK_LEN];
pub type XwingEnc = [u8; XWING_ENC_LEN];

/// X-Wing key generation (§KGen of SD-PKE, line 322).
///
/// Deterministic on `seed`; randomness is supplied by the caller.
pub fn xwing_keygen(_seed: [u8; 32]) -> (XwingSk, XwingPk) {
    unimplemented!()
}

// ===========================================================================
// HPKE Base mode (RFC 9180 §5.1.1), used by §SD-PKE
// ===========================================================================

/// HPKE Base seal: `(enc, ct) = SealBase(pk_r, info, aad, pt)`, as cited
/// at §SD-PKE line 327 with `info=None, aad=None`.
///
/// Randomness is supplied explicitly. RFC 9180's `Encap` consumes 32 bytes
/// for X25519 plus the underlying KEM's randomness; X-Wing wraps both, so
/// 96 bytes is sufficient.
pub fn hpke_seal_base(
    _pk_r: &XwingPk,
    _info: &[u8],
    _aad: &[u8],
    _pt: &[u8],
    _randomness: [u8; 96],
) -> (XwingEnc, Vec<u8>) {
    unimplemented!()
}

/// HPKE Base open: `pt = OpenBase(sk_r, enc, info, aad, ct)`, as cited
/// at §SD-PKE line 331 with `info=None, aad=None`.
pub fn hpke_open_base(
    _sk_r: &XwingSk,
    _enc: &XwingEnc,
    _info: &[u8],
    _aad: &[u8],
    _ct: &[u8],
) -> Option<Vec<u8>> {
    unimplemented!()
}
