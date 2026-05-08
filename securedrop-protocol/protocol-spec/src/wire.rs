//! §Message Formats (lines 616-678): byte-level encodings.
//!
//! These functions are total: encoding produces a fixed-length array,
//! decoding takes a fixed-length array and produces the structured form.
//! Lengths and layouts come directly from the doc.

use crate::keys::{FetchPk, SdApkePk, SdPkePk};
use crate::messaging::Envelope;
use crate::primitives::*;
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

pub fn encode_apke_plaintext(
    _sender_fetch: &FetchPk,
    _sender_pke: &SdPkePk,
    _msg: &[u8],
) -> [u8; SD_APKE_PT_LEN] {
    unimplemented!()
}

pub fn decode_apke_plaintext(
    _bytes: &[u8; SD_APKE_PT_LEN],
) -> (FetchPk, SdPkePk, Vec<u8>) {
    unimplemented!()
}

// ===========================================================================
// §SD-PKE Plaintext (line 636):
// SENDER_LONG_TERM_SD_APKE_DHAKEM_PUBKEY || SENDER_LONG_TERM_SD_APKE_MLKEM768_PUBKEY
// ===========================================================================

/// `32 + 1184` per line 638.
pub const SD_PKE_PT_LEN: usize = AKEM_PK_LEN + KEM_PQ_PK_LEN;

pub fn encode_pke_plaintext(_sender_apke_pk: &SdApkePk) -> [u8; SD_PKE_PT_LEN] {
    unimplemented!()
}

pub fn decode_pke_plaintext(_bytes: &[u8; SD_PKE_PT_LEN]) -> SdApkePk {
    unimplemented!()
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

/// Total envelope length per line 662.
pub const ENVELOPE_LEN: usize =
    R255_POINT_LEN + R255_POINT_LEN + CT_APKE_LEN + CT_PKE_LEN;

pub fn encode_envelope(_e: &Envelope) -> [u8; ENVELOPE_LEN] {
    unimplemented!()
}

pub fn decode_envelope(_bytes: &[u8; ENVELOPE_LEN]) -> Option<Envelope> {
    unimplemented!()
}
