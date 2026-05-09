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

use crate::keys::{PSK_ID, SdApkePk, SdApkeSk};
use crate::primitives::*;
use alloc::vec::Vec;

/// §SD-APKE ciphertext: `((c1, c'), c2)`.
#[derive(Clone)]
pub struct SdApkeCt {
    /// HPKE AuthPSK encapsulation (DH-AKEM).
    pub c1: AkemEnc,
    /// HPKE AuthPSK AEAD ciphertext (`c'`).
    pub cp: Vec<u8>,
    /// ML-KEM-768 encapsulation used as PSK.
    pub c2: KemPqCt,
}

/// `KGen()` — §SD-APKE line 401.
pub fn keygen(seed_dh: [u8; 32], seed_pq: [u8; 64]) -> (SdApkeSk, SdApkePk) {
    let (sk1, pk1) = akem_keygen(seed_dh);
    let (sk2, pk2) = kem_pq_keygen(seed_pq);
    (SdApkeSk { sk1, sk2 }, SdApkePk { pk1, pk2 })
}

/// `AuthEnc(sk, pk, m, ad, info)` — §SD-APKE lines 407-414.
///
/// The `info` argument here is the caller-supplied portion only. The
/// HPKE `info` parameter that actually gets bound to the ciphertext is
/// `c2 || info || pkS2`, constructed inside this function. `pkS2` is
/// the sender's ML-KEM public key; it's passed as `sender_pk.pk2`
/// rather than re-derived from `sender_sk.sk2` since hacspec lacks a
/// generic public-from-private operation for ML-KEM.
pub fn auth_enc(
    sender_sk: &SdApkeSk,
    sender_pk: &SdApkePk,
    recipient_pk: &SdApkePk,
    m: &[u8],
    ad: &[u8],
    info: &[u8],
    randomness_pq: [u8; 32],
    randomness_hpke: [u8; 32],
) -> SdApkeCt {
    // (c2, K2) = KEM_PQ.Encap(pkR = pkR2)
    let (c2, k2) = kem_pq_encap(&recipient_pk.pk2, randomness_pq);

    // full_info = c2 || info || pkS2
    let mut full_info = Vec::new();
    full_info.extend_from_slice(&c2);
    full_info.extend_from_slice(info);
    full_info.extend_from_slice(&sender_pk.pk2);

    // (c1, cp) = pskAEnc(skS=skS1, pkR=pkR1, psk=K2, m=m, ad=ad, info=full_info)
    let (c1, cp) = hpke_seal_auth_psk(
        &recipient_pk.pk1,
        &sender_sk.sk1,
        &k2,
        PSK_ID,
        &full_info,
        ad,
        m,
        randomness_hpke,
    );

    SdApkeCt { c1, cp, c2 }
}

/// `AuthDec(sk, pk, ((c1, cp), c2), ad, info)` — §SD-APKE lines 416-423.
pub fn auth_dec(
    receiver_sk: &SdApkeSk,
    sender_pk: &SdApkePk,
    ct: &SdApkeCt,
    ad: &[u8],
    info: &[u8],
) -> Option<Vec<u8>> {
    // K2 = KEM_PQ.Decap(skR = skR2, enc = c2)
    let k2 = kem_pq_decap(&receiver_sk.sk2, &ct.c2);

    // full_info = c2 || info || pkS2  (must reconstruct the same info as encrypt)
    let mut full_info = Vec::new();
    full_info.extend_from_slice(&ct.c2);
    full_info.extend_from_slice(info);
    full_info.extend_from_slice(&sender_pk.pk2);

    // m = pskADec(pkS=pkS1, skR=skR1, psk=K2, c1=c1, cp=cp, ad=ad, info=full_info)
    hpke_open_auth_psk(
        &receiver_sk.sk1,
        &sender_pk.pk1,
        &k2,
        PSK_ID,
        &ct.c1,
        &full_info,
        ad,
        &ct.cp,
    )
}
