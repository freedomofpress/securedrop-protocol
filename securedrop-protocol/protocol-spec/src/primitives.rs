//! Abstract cryptographic primitives.
//!
//! Each function is an opaque boundary: ProVerif treats them as
//! constructors with axiomatized properties; F* uses pre/postconditions
//! for refinement. The implementation crate provides concrete bodies
//! (libcrux, hpke-rs); this crate never inspects them.
//!
//! Lengths come from the algorithm specs cited in `docs/protocol.md`
//! (§Key Hierarchy, §Wire formats).

use alloc::vec::Vec;

// ===========================================================================
// §Notation: Signature scheme (lines 280-282), tag-prefix per footnote 12
// ===========================================================================

pub const SIG_SK_LEN: usize = 32;
pub const SIG_VK_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

pub type SigSk = [u8; SIG_SK_LEN];
pub type SigVk = [u8; SIG_VK_LEN];
pub type Sig = [u8; SIG_LEN];

pub fn sig_keygen(_seed: [u8; 32]) -> (SigSk, SigVk) {
    unimplemented!()
}

/// Sign per footnote 12: `Sign(sk, len(tag) || tag || m)`.
pub fn sig_sign(_sk: &SigSk, _tag: &[u8], _m: &[u8]) -> Sig {
    unimplemented!()
}

pub fn sig_verify(_vk: &SigVk, _tag: &[u8], _m: &[u8], _s: &Sig) -> bool {
    unimplemented!()
}

// ===========================================================================
// §AKEM: DHKEM(X25519, HKDF-SHA256), line 339
// ===========================================================================

pub const AKEM_SK_LEN: usize = 32;
pub const AKEM_PK_LEN: usize = 32;
pub const AKEM_ENC_LEN: usize = 32;
pub const AKEM_SS_LEN: usize = 32;

pub type AkemSk = [u8; AKEM_SK_LEN];
pub type AkemPk = [u8; AKEM_PK_LEN];
pub type AkemEnc = [u8; AKEM_ENC_LEN];
pub type AkemSs = [u8; AKEM_SS_LEN];

pub fn akem_keygen(_seed: [u8; 32]) -> (AkemSk, AkemPk) {
    unimplemented!()
}

pub fn akem_authencap(
    _sk_s: &AkemSk,
    _pk_r: &AkemPk,
    _randomness: [u8; 32],
) -> (AkemEnc, AkemSs) {
    unimplemented!()
}

pub fn akem_authdecap(_sk_r: &AkemSk, _pk_s: &AkemPk, _c: &AkemEnc) -> AkemSs {
    unimplemented!()
}

// ===========================================================================
// §SD-APKE: ML-KEM-768 (KEM_PQ), line 386
// ===========================================================================

pub const KEM_PQ_SK_LEN: usize = 2400;
pub const KEM_PQ_PK_LEN: usize = 1184;
pub const KEM_PQ_CT_LEN: usize = 1088;
pub const KEM_PQ_SS_LEN: usize = 32;

pub type KemPqSk = [u8; KEM_PQ_SK_LEN];
pub type KemPqPk = [u8; KEM_PQ_PK_LEN];
pub type KemPqCt = [u8; KEM_PQ_CT_LEN];
pub type KemPqSs = [u8; KEM_PQ_SS_LEN];

pub fn kem_pq_keygen(_seed: [u8; 64]) -> (KemPqSk, KemPqPk) {
    unimplemented!()
}

pub fn kem_pq_encap(_pk: &KemPqPk, _randomness: [u8; 32]) -> (KemPqCt, KemPqSs) {
    unimplemented!()
}

pub fn kem_pq_decap(_sk: &KemPqSk, _ct: &KemPqCt) -> KemPqSs {
    unimplemented!()
}

// ===========================================================================
// §SD-PKE: X-Wing(X25519, ML-KEM-768), line 309
// ===========================================================================

pub const XWING_SK_LEN: usize = 32;
pub const XWING_PK_LEN: usize = 1216;
pub const XWING_ENC_LEN: usize = 1120;

pub type XwingSk = [u8; XWING_SK_LEN];
pub type XwingPk = [u8; XWING_PK_LEN];
pub type XwingEnc = [u8; XWING_ENC_LEN];

/// X-Wing key generation (§KGen of SD-PKE, line 322). Deterministic on
/// `seed`.
pub fn xwing_keygen(_seed: [u8; 32]) -> (XwingSk, XwingPk) {
    unimplemented!()
}

// ===========================================================================
// §Notation: Ristretto255 group, line 294
// ===========================================================================

pub const R255_SCALAR_LEN: usize = 32;
pub const R255_POINT_LEN: usize = 32;

pub type R255Scalar = [u8; R255_SCALAR_LEN];
pub type R255Point = [u8; R255_POINT_LEN];

pub fn r255_keygen(_seed: [u8; 32]) -> (R255Scalar, R255Point) {
    unimplemented!()
}

pub fn r255_dh(_sk: &R255Scalar, _pk: &R255Point) -> R255Point {
    unimplemented!()
}

// ===========================================================================
// §Notation: KDF / PBKDF, lines 277-278
// ===========================================================================

pub fn kdf(_ikm: &[u8], _info: &[u8]) -> [u8; 32] {
    unimplemented!()
}

pub fn pbkdf(_passphrase: &[u8]) -> [u8; 64] {
    unimplemented!()
}

// ===========================================================================
// §Notation: AEAD, lines 283-285 (used in §Step 7 challenges)
// ===========================================================================

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

pub fn aead_encrypt(
    _k: &[u8; AEAD_KEY_LEN],
    _n: &[u8; AEAD_NONCE_LEN],
    _ad: &[u8],
    _pt: &[u8],
) -> Vec<u8> {
    unimplemented!()
}

pub fn aead_decrypt(
    _k: &[u8; AEAD_KEY_LEN],
    _n: &[u8; AEAD_NONCE_LEN],
    _ad: &[u8],
    _ct: &[u8],
) -> Option<Vec<u8>> {
    unimplemented!()
}

// ===========================================================================
// HPKE Base mode (§SD-PKE) and AuthPSK mode (§pskAPKE)
// ===========================================================================

/// HPKE Base seal (§SD-PKE, line 327): `(c, c') = SealBase(pkR, info, aad, pt)`.
pub fn hpke_seal_base(
    _pk_r: &XwingPk,
    _info: &[u8],
    _aad: &[u8],
    _pt: &[u8],
    _randomness: [u8; 96],
) -> (XwingEnc, Vec<u8>) {
    unimplemented!()
}

pub fn hpke_open_base(
    _sk_r: &XwingSk,
    _enc: &XwingEnc,
    _info: &[u8],
    _aad: &[u8],
    _ct: &[u8],
) -> Option<Vec<u8>> {
    unimplemented!()
}

/// HPKE AuthPSK seal (§pskAPKE, line 373):
/// `(c1, c') = SealAuthPSK(pkR, info, aad, pt, psk, psk_id, skS)`.
pub fn hpke_seal_auth_psk(
    _pk_r: &AkemPk,
    _sk_s: &AkemSk,
    _psk: &KemPqSs,
    _psk_id: &[u8],
    _info: &[u8],
    _aad: &[u8],
    _pt: &[u8],
    _randomness: [u8; 32],
) -> (AkemEnc, Vec<u8>) {
    unimplemented!()
}

pub fn hpke_open_auth_psk(
    _sk_r: &AkemSk,
    _pk_s: &AkemPk,
    _psk: &KemPqSs,
    _psk_id: &[u8],
    _enc: &AkemEnc,
    _info: &[u8],
    _aad: &[u8],
    _ct: &[u8],
) -> Option<Vec<u8>> {
    unimplemented!()
}
