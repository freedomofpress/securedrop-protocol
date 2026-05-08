//! §Key Setup Steps (lines 149-267).
//!
//! Setup steps that involve a wire exchange (Steps 2 and 3.1) are encoded
//! as a single function whose return type captures both parties' final
//! state, with the over-the-wire arrow inlined. This is the standard
//! single-program functional encoding of a two-party protocol; the
//! information that actually crosses the wire is visible in the function
//! signature (which arguments are pre-existing party state vs. fresh
//! input).

use crate::keys::*;

/// §Step 1 (line 161): FPF signing setup.
pub fn fpf_setup(_seed: [u8; 32]) -> FpfKeys {
    unimplemented!()
}

/// §Step 2 (lines 183-188): Newsroom signing setup.
///
/// Models the wire exchange: NR generates `(sk_NR, vk_NR)`, FPF (after
/// out-of-band manual verification, treated here as having occurred) signs
/// `"fpf-sig-nr" || vk_NR`, and the resulting `σ_FPF^NR` is bundled with
/// the newsroom's keypair.
pub fn newsroom_setup(_nr_seed: [u8; 32], _fpf: &FpfKeys) -> NewsroomKeys {
    unimplemented!()
}

/// §Step 3.1 (lines 214-224): Journalist initial key setup.
///
/// Generates the journalist's three long-term keypairs, the journalist's
/// self-signature `σ_J`, and the newsroom's signature `σ_NR^J` over the
/// journalist's verification key. The doc's manual-verification step is
/// implicit in the `nr` argument being passed in.
pub fn journalist_long_term_setup(
    _seed_sig: [u8; 32],
    _seed_apke_dh: [u8; 32],
    _seed_apke_mlkem: [u8; 64],
    _seed_fetch: [u8; 32],
    _nr: &NewsroomKeys,
) -> JournalistLongTerm {
    unimplemented!()
}

/// §Step 3.2 (lines 239-244): one ephemeral key bundle.
///
/// In production the journalist maintains a pool of `n` of these; this
/// function generates one. The journalist signs the bundle with their
/// long-term `sk_J^sig`.
pub fn journalist_ephemeral_setup(
    _seed_apke_dh: [u8; 32],
    _seed_apke_mlkem: [u8; 64],
    _seed_pke: [u8; 32],
    _j_long: &JournalistLongTerm,
) -> JournalistEphemeral {
    unimplemented!()
}

/// §Step 4 (lines 256-262): Source key setup from passphrase.
///
/// `mk ← PBKDF(passphrase)`, then four domain-separated `KDF(mk, label)`
/// derivations for fetch, APKE-DH, APKE-MLKEM, and PKE.
///
/// Note: the doc's `KDF` returns 32 bytes; ML-KEM-768 keygen requires 64
/// bytes. This spec resolves the gap by calling `KDF` twice with
/// distinguished labels and concatenating, but the doc itself is silent
/// on this point and it should be clarified in `protocol.md`.
pub fn source_setup(_passphrase: &[u8]) -> SourceKeys {
    unimplemented!()
}
