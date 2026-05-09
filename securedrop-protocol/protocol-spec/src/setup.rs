//! §Key Setup Steps (lines 149-267).
//!
//! Setup steps that involve a wire exchange (Steps 2 and 3.1) are encoded
//! as a single function whose return type captures both parties' final
//! state, with the over-the-wire arrow inlined. The information that
//! crosses the wire is visible in the function signature: which arguments
//! are pre-existing party state vs. fresh input.

use crate::keys::*;
use crate::primitives::*;
use alloc::vec::Vec;

/// §Step 1 (line 161): FPF signing setup.
///
/// `(sk_FPF, vk_FPF) ←$ SIG.KGen()`
pub fn fpf_setup(seed: [u8; 32]) -> FpfKeys {
    let (sk, vk) = sig_keygen(seed);
    FpfKeys { sk, vk }
}

/// §Step 2 (lines 183-188): Newsroom signing setup.
///
/// Models the wire exchange: NR generates `(sk_NR, vk_NR)`, FPF (after
/// out-of-band manual verification, treated here as having occurred) signs
/// `"fpf-sig-nr" || vk_NR`, and the resulting `σ_FPF^NR` is bundled with
/// the newsroom's keypair.
pub fn newsroom_setup(nr_seed: [u8; 32], fpf: &FpfKeys) -> NewsroomKeys {
    let (sk, vk) = sig_keygen(nr_seed);
    let sigma_fpf_on_nr = sig_sign(&fpf.sk, TAG_FPF_SIG_NR, &vk);
    NewsroomKeys { sk, vk, sigma_fpf_on_nr }
}

/// §Step 3.1 (lines 214-224): Journalist initial key setup.
///
/// Generates the journalist's three long-term keypairs, the journalist's
/// self-signature `σ_J`, and the newsroom's signature `σ_NR^J` over the
/// journalist's verification key. The doc's manual-verification step is
/// implicit in the `nr` argument being passed in.
pub fn journalist_long_term_setup(
    seed_sig: [u8; 32],
    seed_apke_dh: [u8; 32],
    seed_apke_mlkem: [u8; 64],
    seed_fetch: [u8; 32],
    nr: &NewsroomKeys,
) -> JournalistLongTerm {
    let (sk_sig, vk_sig) = sig_keygen(seed_sig);
    let (sk_apke_dh, pk_apke_dh) = akem_keygen(seed_apke_dh);
    let (sk_apke_pq, pk_apke_pq) = kem_pq_keygen(seed_apke_mlkem);
    let (sk_fetch_raw, pk_fetch_raw) = r255_keygen(seed_fetch);

    let sk_apke = SdApkeSk { sk1: sk_apke_dh, sk2: sk_apke_pq };
    let pk_apke = SdApkePk { pk1: pk_apke_dh, pk2: pk_apke_pq };
    let sk_fetch = FetchSk(sk_fetch_raw);
    let pk_fetch = FetchPk(pk_fetch_raw);

    // preimage = pk_J^APKE || pk_J^fetch
    //          = (pk_apke.pk1 || pk_apke.pk2) || pk_fetch
    let mut preimage = [0u8; AKEM_PK_LEN + KEM_PQ_PK_LEN + R255_POINT_LEN];
    preimage[..AKEM_PK_LEN].copy_from_slice(&pk_apke.pk1);
    preimage[AKEM_PK_LEN..AKEM_PK_LEN + KEM_PQ_PK_LEN].copy_from_slice(&pk_apke.pk2);
    preimage[AKEM_PK_LEN + KEM_PQ_PK_LEN..].copy_from_slice(&pk_fetch.0);

    let sigma_self = sig_sign(&sk_sig, TAG_J_SIG_LTK, &preimage);
    let sigma_nr_on_j = sig_sign(&nr.sk, TAG_NR_SIG, &vk_sig);

    JournalistLongTerm {
        sk_sig,
        vk_sig,
        sk_apke,
        pk_apke,
        sk_fetch,
        pk_fetch,
        sigma_self,
        sigma_nr_on_j,
    }
}

/// §Step 3.2 (lines 239-244): one ephemeral key bundle.
///
/// In production the journalist maintains a pool of `n` of these; this
/// function generates one. The journalist signs the bundle with their
/// long-term `sk_J^sig`.
pub fn journalist_ephemeral_setup(
    seed_apke_dh: [u8; 32],
    seed_apke_mlkem: [u8; 64],
    seed_pke: [u8; 32],
    j_long: &JournalistLongTerm,
) -> JournalistEphemeral {
    let (sk_apke_dh, pk_apke_dh) = akem_keygen(seed_apke_dh);
    let (sk_apke_pq, pk_apke_pq) = kem_pq_keygen(seed_apke_mlkem);
    let (sk_pke_raw, pk_pke_raw) = xwing_keygen(seed_pke);

    let sk_apke_e = SdApkeSk { sk1: sk_apke_dh, sk2: sk_apke_pq };
    let pk_apke_e = SdApkePk { pk1: pk_apke_dh, pk2: pk_apke_pq };
    let sk_pke_e = SdPkeSk(sk_pke_raw);
    let pk_pke_e = SdPkePk(pk_pke_raw);

    // preimage = pk_{J,i}^APKE_E || pk_{J,i}^PKE_E
    let mut preimage = [0u8; AKEM_PK_LEN + KEM_PQ_PK_LEN + XWING_PK_LEN];
    preimage[..AKEM_PK_LEN].copy_from_slice(&pk_apke_e.pk1);
    preimage[AKEM_PK_LEN..AKEM_PK_LEN + KEM_PQ_PK_LEN].copy_from_slice(&pk_apke_e.pk2);
    preimage[AKEM_PK_LEN + KEM_PQ_PK_LEN..].copy_from_slice(&pk_pke_e.0);

    let sigma_eph = sig_sign(&j_long.sk_sig, TAG_J_SIG_EPH, &preimage);

    JournalistEphemeral {
        sk_apke_e,
        pk_apke_e,
        sk_pke_e,
        pk_pke_e,
        sigma_eph,
    }
}

/// §Step 4 (lines 256-262): Source key setup from passphrase.
///
/// `mk ← PBKDF(passphrase)`, then four domain-separated derivations:
/// fetch (32-byte), APKE-DH (32-byte), APKE-MLKEM (64-byte via
/// `kdf_64`), and PKE (32-byte).
///
/// Note: the doc's `KDF` notation is silent on output length. The impl
/// uses Blake2b-64 for the ML-KEM seed, so the spec exposes `kdf_64` as
/// a distinct primitive. This should be clarified in `protocol.md`.
pub fn source_setup(passphrase: &[u8]) -> SourceKeys {
    let mk = pbkdf(passphrase);

    let fetch_seed = kdf(&mk, KDF_SOURCE_FETCH);
    let apke_dh_seed = kdf(&mk, KDF_SOURCE_APKE_DH);
    let apke_mlkem_seed = kdf_64(&mk, KDF_SOURCE_APKE_MLKEM);
    let pke_seed = kdf(&mk, KDF_SOURCE_PKE);

    let (sk_fetch_raw, pk_fetch_raw) = r255_keygen(fetch_seed);
    let (sk_apke_dh, pk_apke_dh) = akem_keygen(apke_dh_seed);
    let (sk_apke_pq, pk_apke_pq) = kem_pq_keygen(apke_mlkem_seed);
    let (sk_pke_raw, pk_pke_raw) = xwing_keygen(pke_seed);

    let mut passphrase_vec = Vec::new();
    passphrase_vec.extend_from_slice(passphrase);

    SourceKeys {
        sk_apke: SdApkeSk { sk1: sk_apke_dh, sk2: sk_apke_pq },
        pk_apke: SdApkePk { pk1: pk_apke_dh, pk2: pk_apke_pq },
        sk_pke: SdPkeSk(sk_pke_raw),
        pk_pke: SdPkePk(pk_pke_raw),
        sk_fetch: FetchSk(sk_fetch_raw),
        pk_fetch: FetchPk(pk_fetch_raw),
        passphrase: passphrase_vec,
    }
}
