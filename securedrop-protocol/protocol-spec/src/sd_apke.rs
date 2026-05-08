//! §SD-APKE: SecureDrop APKE (`docs/protocol.md` lines 381-424).
//!
//! Translates the Python pseudocode at lines 399-424 of the doc.
//!
//! Note the `info` parameter convention. The mathematical signature in
//! the table at line 392 reads `AuthEnc(sk, pk, m, ad, info)`, but the
//! implementation actually constructs the HPKE `info` argument as
//! `c2 || info || pkS2` (line 413). The `<!-- FIXME -->` at line 547
//! flags this. This spec encodes the actual implementation, not the
//! shorthand mathematical signature.
//!
//! ```text
//! def AuthEnc(sk=(skS1, skS2), pk=(pkR1, pkR2), m, ad, info):
//!     pkS2 = skS2.public()
//!     (c2, K2) = KEM_PQ.Encap(pkR=pkR2)
//!     (c1, cp) = pskAEnc(skS=skS1, pkR=pkR1, psk=K2,
//!                        m=m, ad=ad, info=c2 + info + pkS2)
//!     return ((c1, cp), c2)
//!
//! def AuthDec(sk=(skR1, skR2), pk=(pkS1, pkS2), c1, cp, c2, ad, info):
//!     K2 = KEM_PQ.Decap(skR=skR2, enc=c2)
//!     m = pskADec(pkS=pkS1, skR=skR1, psk=K2,
//!                 c1=c1, cp=cp, ad=ad, info=c2 + info + pkS2)
//!     return m
//! ```

use crate::keys::{SdApkePk, SdApkeSk};
use crate::primitives::*;
use alloc::vec::Vec;

/// §SD-APKE ciphertext: `((c1, c'), c2)`.
pub struct SdApkeCt {
    /// HPKE AuthPSK encapsulation (DH-AKEM).
    pub c1: AkemEnc,
    /// HPKE AuthPSK AEAD ciphertext (`c'`).
    pub cp: Vec<u8>,
    /// ML-KEM-768 encapsulation used as PSK.
    pub c2: KemPqCt,
}

pub fn keygen(_seed_dh: [u8; 32], _seed_pq: [u8; 64]) -> (SdApkeSk, SdApkePk) {
    unimplemented!()
}

/// §AuthEnc (lines 407-414).
///
/// The `info` argument here is the caller-supplied portion only. The
/// HPKE `info` parameter that actually gets bound to the ciphertext is
/// `c2 || info || pkS2`, constructed inside this function. `pkS2` is
/// the sender's ML-KEM public key (passed as `sender_pk.pk2` rather
/// than re-derived from `sk.sk2` since hacspec lacks a generic
/// public-from-private operation for ML-KEM).
pub fn auth_enc(
    _sk_s: &SdApkeSk,
    _pk_s: &SdApkePk,
    _pk_r: &SdApkePk,
    _m: &[u8],
    _ad: &[u8],
    _info: &[u8],
    _randomness_pq: [u8; 32],
    _randomness_hpke: [u8; 32],
) -> SdApkeCt {
    unimplemented!()
}

/// §AuthDec (lines 416-423).
pub fn auth_dec(
    _sk_r: &SdApkeSk,
    _pk_s: &SdApkePk,
    _ct: &SdApkeCt,
    _ad: &[u8],
    _info: &[u8],
) -> Option<Vec<u8>> {
    unimplemented!()
}
