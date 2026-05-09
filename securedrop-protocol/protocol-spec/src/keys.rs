//! Key types per §Key Hierarchy (lines 117-142) and protocol-step records.
//!
//! Each long-term party record (FPF, Newsroom, Journalist, Source) holds
//! the keys named in the doc plus the signatures the party has accumulated
//! at the end of its setup step.

use crate::primitives::*;
use alloc::vec::Vec;

// ===========================================================================
// SD-APKE keypair: pk = (pk1 = DH-AKEM, pk2 = ML-KEM-768)
// §Key Hierarchy and §SD-APKE (line 392)
// ===========================================================================

#[derive(Clone)]
pub struct SdApkeSk {
    pub sk1: AkemSk,
    pub sk2: KemPqSk,
}

#[derive(Clone)]
pub struct SdApkePk {
    pub pk1: AkemPk,
    pub pk2: KemPqPk,
}

// ===========================================================================
// SD-PKE keypair: X-Wing  (§SD-PKE)
// ===========================================================================

#[derive(Clone)]
pub struct SdPkeSk(pub XwingSk);

#[derive(Clone)]
pub struct SdPkePk(pub XwingPk);

// ===========================================================================
// Fetch keypair: ristretto255  (§Notation, line 294)
// ===========================================================================

#[derive(Clone)]
pub struct FetchSk(pub R255Scalar);

#[derive(Clone)]
pub struct FetchPk(pub R255Point);

// ===========================================================================
// Per-party long-term records
// ===========================================================================

/// §Step 1 (line 161): FPF root of trust.
pub struct FpfKeys {
    pub sk: SigSk,
    pub vk: SigVk,
}

/// §Step 2 (lines 183-188): newsroom, with the signature FPF issued over its vk.
pub struct NewsroomKeys {
    pub sk: SigSk,
    pub vk: SigVk,
    /// `σ_FPF^NR ← Sign(sk_FPF, "fpf-sig-nr" || vk_NR)`
    pub sigma_fpf_on_nr: Sig,
}

/// §Step 3.1 (lines 214-224): journalist long-term identity.
pub struct JournalistLongTerm {
    pub sk_sig: SigSk,
    pub vk_sig: SigVk,
    pub sk_apke: SdApkeSk,
    pub pk_apke: SdApkePk,
    pub sk_fetch: FetchSk,
    pub pk_fetch: FetchPk,
    /// `σ_J ← Sign(sk_J^sig, "j-sig-ltk" || (pk_J^APKE || pk_J^fetch))`
    pub sigma_self: Sig,
    /// `σ_NR^J ← Sign(sk_NR^sig, "nr-sig" || vk_J^sig)`
    pub sigma_nr_on_j: Sig,
}

/// §Step 3.2 (lines 239-244): one ephemeral key bundle of size N.
/// Journalists maintain a pool of these.
pub struct JournalistEphemeral {
    pub sk_apke_e: SdApkeSk,
    pub pk_apke_e: SdApkePk,
    pub sk_pke_e: SdPkeSk,
    pub pk_pke_e: SdPkePk,
    /// `σ_{J,i} ← Sign(sk_J^sig, "j-sig-eph" || (pk_{J,i}^APKE_E || pk_{J,i}^PKE_E))`
    pub sigma_eph: Sig,
}

/// §Step 4 (lines 256-262): source keys, all derived from the passphrase.
pub struct SourceKeys {
    pub sk_apke: SdApkeSk,
    pub pk_apke: SdApkePk,
    pub sk_pke: SdPkeSk,
    pub pk_pke: SdPkePk,
    pub sk_fetch: FetchSk,
    pub pk_fetch: FetchPk,
    pub passphrase: Vec<u8>,
}

// ===========================================================================
// Domain tags (footnote 12: `len(tag) || tag || m` is applied uniformly
// inside `sig_sign`, so callers pass the bare tag bytes here).
// ===========================================================================

/// §Step 2: FPF's signature over a newsroom verification key.
pub const TAG_FPF_SIG_NR: &[u8] = b"fpf-sig-nr";
/// §Step 3.1: Newsroom's signature over a journalist verification key.
pub const TAG_NR_SIG: &[u8] = b"nr-sig";
/// §Step 3.1: Journalist's self-signature over their long-term public keys.
pub const TAG_J_SIG_LTK: &[u8] = b"j-sig-ltk";
/// §Step 3.2: Journalist's signature over an ephemeral key bundle.
pub const TAG_J_SIG_EPH: &[u8] = b"j-sig-eph";

// ===========================================================================
// KDF labels (§Step 4, lines 259-262)
// ===========================================================================

pub const KDF_SOURCE_FETCH: &[u8] = b"sourcefetchkey";
pub const KDF_SOURCE_APKE_DH: &[u8] = b"sourceAPKEkey-dh";
pub const KDF_SOURCE_APKE_MLKEM: &[u8] = b"sourceAPKEkey-mlkem";
pub const KDF_SOURCE_PKE: &[u8] = b"sourcePKEkey";

// ===========================================================================
// PSK ID for SD-APKE (§pskAPKE, line 370)
// ===========================================================================

pub const PSK_ID: &[u8] = b"SD-pskAPKE";
