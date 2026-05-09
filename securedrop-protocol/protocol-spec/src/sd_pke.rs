//! §SD-PKE: SecureDrop PKE (`docs/protocol.md` lines 304-333).
//!
//! Translates the Python pseudocode at lines 321-333 of the doc:
//!
//! ```text
//! def KGen():
//!     (skS, pkS) = KEM_H.KGen()
//!     return (skS, pkS)
//!
//! def Enc(pkR, m):
//!     c, cp = HPKE.SealBase(pkR=pkR, info=None, aad=None, pt=m)
//!     return (c, cp)
//!
//! def Dec(skR, c, cp):
//!     m = HPKE.OpenBase(enc=c, skR=skR, info=None, aad=None, ct=cp)
//!     return m
//! ```
//!
//! Per footnote 9 of the doc, `None` in the Python pseudocode and `-` in
//! the mathematical syntax both denote the empty string; we encode them
//! as `&[]`.
//!
//! `KEM_H = X-Wing` and `AEAD = AES-GCM` (§SD-PKE line 309). Those are
//! parameters of the abstract HPKE primitive in `primitives` and not
//! visible here.

use crate::keys::{SdPkePk, SdPkeSk};
use crate::primitives::{XwingEnc, hpke_open_base, hpke_seal_base, xwing_keygen};
use alloc::vec::Vec;

/// SD-PKE ciphertext `(c, c')` per §SD-PKE line 317.
#[derive(Clone)]
pub struct SdPkeCt {
    /// Encapsulated X-Wing shared secret (`c` in the spec).
    pub c: XwingEnc,
    /// HPKE Base AEAD ciphertext (`c'` in the spec).
    pub cp: Vec<u8>,
}

/// `KGen()` — §SD-PKE line 322.
pub fn keygen(seed: [u8; 32]) -> (SdPkeSk, SdPkePk) {
    let (sk, pk) = xwing_keygen(seed);
    (SdPkeSk(sk), SdPkePk(pk))
}

/// `Enc(pkR, m)` — §SD-PKE line 326.
///
/// Randomness is supplied explicitly; the doc's `←$` is encoded as a
/// caller-passed `[u8; 96]` (sufficient for X-Wing per RFC 9180 §4.1
/// + the I-D for X-Wing).
pub fn enc(pk_r: &SdPkePk, m: &[u8], randomness: [u8; 96]) -> SdPkeCt {
    let (c, cp) = hpke_seal_base(&pk_r.0, &[], &[], m, randomness);
    SdPkeCt { c, cp }
}

/// `Dec(skR, c, cp)` — §SD-PKE line 330.
pub fn dec(sk_r: &SdPkeSk, ct: &SdPkeCt) -> Option<Vec<u8>> {
    hpke_open_base(&sk_r.0, &ct.c, &[], &[], &ct.cp)
}
