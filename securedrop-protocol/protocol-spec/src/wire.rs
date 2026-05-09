//! §Message Formats (lines 616-678): byte-level encodings.
//!
//! These functions are total: encoding produces a fixed-length array,
//! decoding takes a fixed-length array and produces the structured form.
//! Lengths and layouts come directly from the doc.

use crate::keys::{FetchPk, SdApkePk, SdPkePk};
use crate::messaging::Envelope;
use crate::primitives::*;
use crate::sd_apke::SdApkeCt;
use alloc::vec::Vec;

// ===========================================================================
// §SD-APKE Plaintext (line 626):
// SENDER_FETCH_PUBKEY || SENDER_PKE_PUBKEY || message || padding
// ===========================================================================

/// Padded message length. The doc requires fixed-size message padding
/// before encryption (line 630); the exact value is a deployment choice.
pub const FIXED_MSG_LEN: usize = 1024;

/// `32 + 1216 + FIXED_MSG_LEN` per line 628.
pub const SD_APKE_PT_LEN: usize = R255_POINT_LEN + XWING_PK_LEN + FIXED_MSG_LEN;

/// Encode `pt = SENDER_FETCH || SENDER_PKE || msg`, zero-padded to
/// `SD_APKE_PT_LEN`. Truncates `msg` if it would exceed `FIXED_MSG_LEN`.
///
/// Note: the doc does not specify a padding scheme. This spec uses
/// trailing-zero padding; the lossless recovery of the original message
/// length is a known gap (see `decode_apke_plaintext`).
pub fn encode_apke_plaintext(
    sender_fetch: &FetchPk,
    sender_pke: &SdPkePk,
    msg: &[u8],
) -> [u8; SD_APKE_PT_LEN] {
    let mut out = [0u8; SD_APKE_PT_LEN];
    out[..R255_POINT_LEN].copy_from_slice(&sender_fetch.0);
    out[R255_POINT_LEN..R255_POINT_LEN + XWING_PK_LEN].copy_from_slice(&sender_pke.0);

    let msg_offset = R255_POINT_LEN + XWING_PK_LEN;
    let msg_len = if msg.len() > FIXED_MSG_LEN {
        FIXED_MSG_LEN
    } else {
        msg.len()
    };
    out[msg_offset..msg_offset + msg_len].copy_from_slice(&msg[..msg_len]);

    out
}

/// Decode an SD-APKE plaintext.
///
/// The returned `Vec<u8>` is the full padded message slot
/// (`FIXED_MSG_LEN` bytes). The caller is responsible for stripping
/// padding; this spec does not encode message length, matching the
/// doc's silence on padding scheme.
pub fn decode_apke_plaintext(
    bytes: &[u8; SD_APKE_PT_LEN],
) -> (FetchPk, SdPkePk, Vec<u8>) {
    let mut fetch_bytes = [0u8; R255_POINT_LEN];
    fetch_bytes.copy_from_slice(&bytes[..R255_POINT_LEN]);

    let mut pke_bytes = [0u8; XWING_PK_LEN];
    pke_bytes.copy_from_slice(&bytes[R255_POINT_LEN..R255_POINT_LEN + XWING_PK_LEN]);

    let msg_offset = R255_POINT_LEN + XWING_PK_LEN;
    let mut msg = Vec::new();
    msg.extend_from_slice(&bytes[msg_offset..]);

    (FetchPk(fetch_bytes), SdPkePk(pke_bytes), msg)
}

// ===========================================================================
// §SD-PKE Plaintext (line 636):
// SENDER_LONG_TERM_SD_APKE_DHAKEM_PUBKEY || SENDER_LONG_TERM_SD_APKE_MLKEM768_PUBKEY
// ===========================================================================

/// `32 + 1184` per line 638.
pub const SD_PKE_PT_LEN: usize = AKEM_PK_LEN + KEM_PQ_PK_LEN;

pub fn encode_pke_plaintext(sender_apke_pk: &SdApkePk) -> [u8; SD_PKE_PT_LEN] {
    let mut out = [0u8; SD_PKE_PT_LEN];
    out[..AKEM_PK_LEN].copy_from_slice(&sender_apke_pk.pk1);
    out[AKEM_PK_LEN..].copy_from_slice(&sender_apke_pk.pk2);
    out
}

pub fn decode_pke_plaintext(bytes: &[u8; SD_PKE_PT_LEN]) -> SdApkePk {
    let mut pk1 = [0u8; AKEM_PK_LEN];
    pk1.copy_from_slice(&bytes[..AKEM_PK_LEN]);
    let mut pk2 = [0u8; KEM_PQ_PK_LEN];
    pk2.copy_from_slice(&bytes[AKEM_PK_LEN..]);
    SdApkePk { pk1, pk2 }
}

// ===========================================================================
// §Encrypted Envelope (line 660):
// X || Z || CT_APKE || CT_PKE
// ===========================================================================

/// CT_APKE per line 644: `MLKEM768_CT || DHAKEM_ENCAPS || CT_SD_APKE`.
pub const CT_APKE_LEN: usize =
    KEM_PQ_CT_LEN + AKEM_ENC_LEN + (FIXED_MSG_LEN + AEAD_TAG_LEN);

/// CT_PKE per line 654: `XWING_SS_ENCAPS_CT || (DHAKEM_PK + MLKEM768_PK + AEAD_TAG_LEN)`.
pub const CT_PKE_LEN: usize =
    XWING_ENC_LEN + AKEM_PK_LEN + KEM_PQ_PK_LEN + AEAD_TAG_LEN;

/// CT_SD_APKE: the AEAD ciphertext portion of CT_APKE
/// (excluding the two encapsulations).
pub const CT_SD_APKE_LEN: usize = FIXED_MSG_LEN + AEAD_TAG_LEN;

/// CT_SD_PKE: the AEAD ciphertext portion of CT_PKE
/// (excluding the X-Wing encapsulation).
pub const CT_SD_PKE_LEN: usize = AKEM_PK_LEN + KEM_PQ_PK_LEN + AEAD_TAG_LEN;

/// Total envelope length per line 662.
pub const ENVELOPE_LEN: usize =
    R255_POINT_LEN + R255_POINT_LEN + CT_APKE_LEN + CT_PKE_LEN;

pub fn encode_envelope(e: &Envelope) -> [u8; ENVELOPE_LEN] {
    let mut out = [0u8; ENVELOPE_LEN];
    let mut offset = 0;

    // X
    out[offset..offset + R255_POINT_LEN].copy_from_slice(&e.hint_x);
    offset += R255_POINT_LEN;

    // Z
    out[offset..offset + R255_POINT_LEN].copy_from_slice(&e.hint_z);
    offset += R255_POINT_LEN;

    // CT_APKE = c2 (ML-KEM) || c1 (DH-AKEM) || cp (AEAD ct)
    out[offset..offset + KEM_PQ_CT_LEN].copy_from_slice(&e.ct_apke.c2);
    offset += KEM_PQ_CT_LEN;
    out[offset..offset + AKEM_ENC_LEN].copy_from_slice(&e.ct_apke.c1);
    offset += AKEM_ENC_LEN;
    let cp_copy = if e.ct_apke.cp.len() > CT_SD_APKE_LEN {
        CT_SD_APKE_LEN
    } else {
        e.ct_apke.cp.len()
    };
    out[offset..offset + cp_copy].copy_from_slice(&e.ct_apke.cp[..cp_copy]);
    offset += CT_SD_APKE_LEN;

    // CT_PKE = pke_c (X-Wing encaps) || pke_cp (AEAD ct)
    let (pke_c, pke_cp) = &e.ct_pke;
    out[offset..offset + XWING_ENC_LEN].copy_from_slice(pke_c);
    offset += XWING_ENC_LEN;
    let pke_cp_copy = if pke_cp.len() > CT_SD_PKE_LEN {
        CT_SD_PKE_LEN
    } else {
        pke_cp.len()
    };
    out[offset..offset + pke_cp_copy].copy_from_slice(&pke_cp[..pke_cp_copy]);

    out
}

pub fn decode_envelope(bytes: &[u8; ENVELOPE_LEN]) -> Option<Envelope> {
    let mut offset = 0;

    let mut hint_x = [0u8; R255_POINT_LEN];
    hint_x.copy_from_slice(&bytes[offset..offset + R255_POINT_LEN]);
    offset += R255_POINT_LEN;

    let mut hint_z = [0u8; R255_POINT_LEN];
    hint_z.copy_from_slice(&bytes[offset..offset + R255_POINT_LEN]);
    offset += R255_POINT_LEN;

    // CT_APKE
    let mut c2 = [0u8; KEM_PQ_CT_LEN];
    c2.copy_from_slice(&bytes[offset..offset + KEM_PQ_CT_LEN]);
    offset += KEM_PQ_CT_LEN;

    let mut c1 = [0u8; AKEM_ENC_LEN];
    c1.copy_from_slice(&bytes[offset..offset + AKEM_ENC_LEN]);
    offset += AKEM_ENC_LEN;

    let mut cp = Vec::new();
    cp.extend_from_slice(&bytes[offset..offset + CT_SD_APKE_LEN]);
    offset += CT_SD_APKE_LEN;

    // CT_PKE
    let mut pke_c = [0u8; XWING_ENC_LEN];
    pke_c.copy_from_slice(&bytes[offset..offset + XWING_ENC_LEN]);
    offset += XWING_ENC_LEN;

    let mut pke_cp = Vec::new();
    pke_cp.extend_from_slice(&bytes[offset..offset + CT_SD_PKE_LEN]);

    Some(Envelope {
        ct_apke: SdApkeCt { c1, cp, c2 },
        ct_pke: (pke_c, pke_cp),
        hint_x,
        hint_z,
    })
}
