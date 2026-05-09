//! §Messaging Protocol (Steps 5-7, lines 426-614).
//!
//! Each "row" of the doc's two-column tables maps to a function on the
//! sender, server, or receiver side. Wire messages are explicit data
//! types (the analog of Tamarin facts); functions are the analog of
//! Tamarin rules. The doc's set notation (`pks`, `sigs`, `challs`,
//! `cids`, `fetched`) is encoded as fixed-length arrays of `Option<T>`,
//! matching the doc's pad-to-MAX-MESSAGES requirement (line 614,
//! line 672).
//!
//! `←$` random sampling in the doc becomes explicit `[u8; N]` randomness
//! parameters; callers split them deterministically inside.

use crate::keys::*;
use crate::primitives::*;
use crate::sd_apke::SdApkeCt;
use alloc::vec::Vec;

// ===========================================================================
// Sizing constants
// ===========================================================================

/// Number of journalists with active key bundles. Fixed-length encoding
/// of the `pks` and `sigs` sets in §Step 5.
pub const N_JOURNALISTS: usize = 8;

/// Server-side cap on stored messages. The doc references `MAX_MESSAGES`
/// throughout §Step 7 (lines 577, 614, 672). Set conservatively here for
/// stack-friendly executable testing; production deployments will set
/// this higher.
pub const MAX_MESSAGES: usize = 16;

/// Random bytes per challenge slot needed by `server_compute_challenges`:
///   r_k (32) + z_seed (32) + x_seed (32) + id_k (16) = 112
pub const CHALLENGE_RNG_PER_SLOT: usize = 32 + 32 + 32 + 16;

/// Random bytes consumed by `sender_encrypt_for_recipient`. Layout:
///   [0..32):    SD-APKE ML-KEM encap
///   [32..64):   SD-APKE HPKE AuthPSK seal
///   [64..160):  SD-PKE HPKE Base seal (96 bytes)
///   [160..192): Ristretto255 hint scalar
pub const ENCRYPT_RNG_LEN: usize = 192;

// ===========================================================================
// §Step 5: wire types
// ===========================================================================

/// One row of `pks` from §Step 5 (line 451).
#[derive(Clone)]
pub struct PkBundleEntry {
    pub vk_j_sig: SigVk,
    pub pk_j_apke_e: SdApkePk,
    pub pk_j_pke_e: SdPkePk,
    pub pk_j_fetch: FetchPk,
    pub pk_j_apke: SdApkePk,
}

/// One row of `sigs` from §Step 5 (line 452).
#[derive(Clone)]
pub struct SigBundleEntry {
    pub sigma_nr_on_j: Sig,
    pub sigma_j: Sig,
    pub sigma_j_eph: Sig,
}

/// Server response to `RequestKeys` (§Step 5).
pub struct KeysResponse {
    pub pks: [Option<PkBundleEntry>; N_JOURNALISTS],
    pub sigs: [Option<SigBundleEntry>; N_JOURNALISTS],
}

/// §Step 5 abort reasons (lines 455-457).
#[derive(Debug)]
pub enum AbortReason {
    /// `SIG.Vfy(vk_NR^sig, "nr-sig" || vk_J^sig, σ_NR^J) = 0`.
    BadNrSig,
    /// `SIG.Vfy(vk_J^sig, "j-sig-ltk" || (pk_J^APKE || pk_J^fetch), σ_J) = 0`.
    BadJSig,
    /// `SIG.Vfy(vk_J^sig, "j-sig-eph" || (pk_{J,i}^APKE_E || pk_{J,i}^PKE_E), σ_{J,i}) = 0`.
    BadJEphSig,
}

// ===========================================================================
// §Step 6: wire types
// ===========================================================================

/// §Step 6 final wire payload `(C_S, X, Z)` from line 543.
#[derive(Clone)]
pub struct Envelope {
    /// `ct^APKE` from §Step 6, line 538.
    pub ct_apke: SdApkeCt,
    /// `ct^PKE = (c, c')` from §Step 6, line 539.
    pub ct_pke: (XwingEnc, Vec<u8>),
    /// `X = g^x` (Ristretto255 ephemeral pubkey).
    pub hint_x: R255Point,
    /// `Z = (pk_R^fetch)^x` (Ristretto255 DH share).
    pub hint_z: R255Point,
}

/// Server-generated message identifier (§Step 6, line 544; §Wire, line 670).
pub type MessageId = [u8; 16];

/// One row in the server's message database (§Wire, line 670).
#[derive(Clone)]
pub struct ServerRow {
    pub id: MessageId,
    pub envelope: Envelope,
}

/// Server message database, fixed-size per the doc's pad-to-MAX_MESSAGES
/// requirement (line 614, line 672).
pub struct ServerDb {
    pub rows: [Option<ServerRow>; MAX_MESSAGES],
}

impl ServerDb {
    pub fn new() -> Self {
        Self { rows: [const { None }; MAX_MESSAGES] }
    }
}

impl Default for ServerDb {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// §Step 7: wire types
// ===========================================================================

/// AEAD output length for an encrypted `MessageId`.
/// The doc fixes the nonce as `0^nl` (line 588), so it is not part of
/// the wire encoding; only `ciphertext || tag` is transmitted.
pub const EID_LEN: usize = 16 + AEAD_TAG_LEN;

/// Per-message challenge `(eid_k, Q_k)` (§Step 7, line 589).
#[derive(Clone)]
pub struct Challenge {
    /// `eid_k = AEAD.Enc(idk_k, 0^nl, -, id_k)` (§line 588).
    pub eid: [u8; EID_LEN],
    /// `Q_k = X_k^{r_k}` (§line 580).
    pub q: R255Point,
}

/// Server's response to `RequestMessages` (§Step 7).
pub struct Challenges {
    pub items: [Option<Challenge>; MAX_MESSAGES],
}

/// Result of decrypting an envelope (§Step 7, line 608).
/// `pt = pk_S^fetch || pk_S^PKE || m` (per the byte format at line 626;
/// line 608 of the doc gives the components in a different order, which
/// is informal pseudocode — the wire format is authoritative).
pub struct DecryptedMessage {
    pub msg: Vec<u8>,
    pub sender_pk_fetch: FetchPk,
    pub sender_pk_pke: SdPkePk,
}

// ===========================================================================
// §Step 5: signature-chain verification
// ===========================================================================

/// Server side of §Step 5 (lines 450-453): for each journalist, select
/// one ephemeral key bundle indexed by `rng[j] % pool_len`, return
/// `(pks, sigs)`.
///
/// Note: the doc's "remove key bundle i from storage" (line 453) is not
/// modelled here, since the ephemeral pools are passed in as borrowed
/// state rather than threaded through `ServerDb`. A more faithful
/// encoding would carry the pools in `ServerDb` and consume an
/// ephemeral on each `RequestKeys`. This is a known modelling gap.
pub fn server_select_keys(
    db: ServerDb,
    ephemerals_per_j: &[Vec<JournalistEphemeral>; N_JOURNALISTS],
    journalists: &[Option<JournalistLongTerm>; N_JOURNALISTS],
    rng: [u8; 32],
) -> (KeysResponse, ServerDb) {
    let mut pks: [Option<PkBundleEntry>; N_JOURNALISTS] =
        core::array::from_fn(|_| None);
    let mut sigs: [Option<SigBundleEntry>; N_JOURNALISTS] =
        core::array::from_fn(|_| None);

    let mut j = 0;
    while j < N_JOURNALISTS {
        if let Some(jl) = &journalists[j] {
            let pool = &ephemerals_per_j[j];
            if !pool.is_empty() {
                let idx = (rng[j] as usize) % pool.len();
                let eph = &pool[idx];

                pks[j] = Some(PkBundleEntry {
                    vk_j_sig: jl.vk_sig,
                    pk_j_apke_e: eph.pk_apke_e.clone(),
                    pk_j_pke_e: eph.pk_pke_e.clone(),
                    pk_j_fetch: jl.pk_fetch.clone(),
                    pk_j_apke: jl.pk_apke.clone(),
                });
                sigs[j] = Some(SigBundleEntry {
                    sigma_nr_on_j: jl.sigma_nr_on_j,
                    sigma_j: jl.sigma_self,
                    sigma_j_eph: eph.sigma_eph,
                });
            }
        }
        j += 1;
    }

    (KeysResponse { pks, sigs }, db)
}

/// Sender side of §Step 5 (lines 455-457): verify all three signature
/// chains. Aborts on the first failure.
pub fn sender_verify_keys(
    vk_nr: &SigVk,
    resp: &KeysResponse,
) -> Result<(), AbortReason> {
    let mut j = 0;
    while j < N_JOURNALISTS {
        if let (Some(pk_entry), Some(sig_entry)) = (&resp.pks[j], &resp.sigs[j]) {
            // σ_NR^J: SIG.Vfy(vk_NR, "nr-sig" || vk_J^sig, σ_NR^J)
            if !sig_verify(
                vk_nr,
                TAG_NR_SIG,
                &pk_entry.vk_j_sig,
                &sig_entry.sigma_nr_on_j,
            ) {
                return Err(AbortReason::BadNrSig);
            }

            // σ_J: SIG.Vfy(vk_J^sig, "j-sig-ltk" || (pk_J^APKE || pk_J^fetch), σ_J)
            let mut ltk_preimage = [0u8; AKEM_PK_LEN + KEM_PQ_PK_LEN + R255_POINT_LEN];
            ltk_preimage[..AKEM_PK_LEN].copy_from_slice(&pk_entry.pk_j_apke.pk1);
            ltk_preimage[AKEM_PK_LEN..AKEM_PK_LEN + KEM_PQ_PK_LEN]
                .copy_from_slice(&pk_entry.pk_j_apke.pk2);
            ltk_preimage[AKEM_PK_LEN + KEM_PQ_PK_LEN..]
                .copy_from_slice(&pk_entry.pk_j_fetch.0);

            if !sig_verify(
                &pk_entry.vk_j_sig,
                TAG_J_SIG_LTK,
                &ltk_preimage,
                &sig_entry.sigma_j,
            ) {
                return Err(AbortReason::BadJSig);
            }

            // σ_{J,i}: SIG.Vfy(vk_J^sig, "j-sig-eph" || (pk_apke_e || pk_pke_e), σ_eph)
            let mut eph_preimage = [0u8; AKEM_PK_LEN + KEM_PQ_PK_LEN + XWING_PK_LEN];
            eph_preimage[..AKEM_PK_LEN].copy_from_slice(&pk_entry.pk_j_apke_e.pk1);
            eph_preimage[AKEM_PK_LEN..AKEM_PK_LEN + KEM_PQ_PK_LEN]
                .copy_from_slice(&pk_entry.pk_j_apke_e.pk2);
            eph_preimage[AKEM_PK_LEN + KEM_PQ_PK_LEN..]
                .copy_from_slice(&pk_entry.pk_j_pke_e.0);

            if !sig_verify(
                &pk_entry.vk_j_sig,
                TAG_J_SIG_EPH,
                &eph_preimage,
                &sig_entry.sigma_j_eph,
            ) {
                return Err(AbortReason::BadJEphSig);
            }
        }
        j += 1;
    }
    Ok(())
}

// ===========================================================================
// §Step 6: send a message
// ===========================================================================

/// §Step 6 (lines 537-545): produce one envelope addressed to one
/// recipient. The caller iterates this over `pks` (and substitutes the
/// reply target's keys for their own slot in the reply case, lines
/// 533-535).
///
/// `randomness` is split deterministically inside between the SD-APKE
/// ML-KEM encapsulation, the HPKE AuthPSK seal, the SD-PKE seal, and
/// the Ristretto255 hint keypair generation. See `ENCRYPT_RNG_LEN`.
pub fn sender_encrypt_for_recipient(
    sender_sk_apke: &SdApkeSk,
    sender_pk_apke: &SdApkePk,
    sender_pk_fetch: &FetchPk,
    sender_pk_pke: &SdPkePk,
    recipient: &PkBundleEntry,
    nr_id: &[u8],
    message: &[u8],
    randomness: [u8; ENCRYPT_RNG_LEN],
) -> Envelope {
    // Split randomness
    let mut r_apke_pq = [0u8; 32];
    r_apke_pq.copy_from_slice(&randomness[0..32]);
    let mut r_apke_hpke = [0u8; 32];
    r_apke_hpke.copy_from_slice(&randomness[32..64]);
    let mut r_pke = [0u8; 96];
    r_pke.copy_from_slice(&randomness[64..160]);
    let mut r_hint = [0u8; 32];
    r_hint.copy_from_slice(&randomness[160..192]);

    // pt = pk_S^fetch || pk_S^PKE || m, padded to FIXED_MSG_LEN
    let pt = crate::wire::encode_apke_plaintext(sender_pk_fetch, sender_pk_pke, message);

    // ct^APKE = SD-APKE.AuthEnc(sk_S^APKE, pk_R^APKE, pt, NR, pk_R^fetch)
    let ct_apke = crate::sd_apke::auth_enc(
        sender_sk_apke,
        sender_pk_apke,
        &recipient.pk_j_apke_e,
        &pt,
        nr_id,
        &recipient.pk_j_fetch.0,
        r_apke_pq,
        r_apke_hpke,
    );

    // ct^PKE = SD-PKE.Enc(pk_R^PKE, pk_S^APKE)
    let pke_pt = crate::wire::encode_pke_plaintext(sender_pk_apke);
    let ct_pke_full = crate::sd_pke::enc(&recipient.pk_j_pke_e, &pke_pt, r_pke);

    // (x, X) ← Ristretto255.KGen(); Z = (pk_R^fetch)^x
    let (hint_sk, hint_x) = r255_keygen(r_hint);
    let hint_z = r255_dh(&hint_sk, &recipient.pk_j_fetch.0);

    Envelope {
        ct_apke,
        ct_pke: (ct_pke_full.c, ct_pke_full.cp),
        hint_x,
        hint_z,
    }
}

/// Server side of §Step 6 (lines 544-545): generate a fresh message ID
/// and store the row in the first available slot. Returns the updated
/// database. If the database is full, the envelope is dropped (the
/// doc treats `MAX_MESSAGES` as a hard cap).
pub fn server_store_message(
    db: ServerDb,
    envelope: Envelope,
    id_seed: [u8; 16],
) -> ServerDb {
    let mut new_db = db;

    let mut empty_idx: Option<usize> = None;
    let mut k = 0;
    while k < MAX_MESSAGES {
        if new_db.rows[k].is_none() {
            empty_idx = Some(k);
            break;
        }
        k += 1;
    }

    if let Some(idx) = empty_idx {
        new_db.rows[idx] = Some(ServerRow { id: id_seed, envelope });
    }
    new_db
}

// ===========================================================================
// §Step 7: fetch and decrypt
// ===========================================================================

/// Server side of §Step 7 (lines 577-589): construct the `MAX_MESSAGES`
/// challenges, padding with random values for empty slots (lines
/// 581-588). Constant-time per the requirement at line 614.
///
/// `rng` must contain at least `CHALLENGE_RNG_PER_SLOT * MAX_MESSAGES`
/// bytes.
pub fn server_compute_challenges(
    db: &ServerDb,
    nr_id: &[u8],
    rng: &[u8],
) -> Challenges {
    let mut items: [Option<Challenge>; MAX_MESSAGES] = [const { None }; MAX_MESSAGES];

    let mut k = 0;
    while k < MAX_MESSAGES {
        let base = k * CHALLENGE_RNG_PER_SLOT;

        // r_k from rng[base..base+32]
        let mut r_k = [0u8; 32];
        r_k.copy_from_slice(&rng[base..base + 32]);

        let q_k: R255Point;
        let z_k: R255Point;
        let id_k: MessageId;

        match &db.rows[k] {
            Some(row) => {
                // Q_k = X_k^{r_k}; Z_k = stored Z; id_k = stored id
                q_k = r255_dh(&r_k, &row.envelope.hint_x);
                z_k = row.envelope.hint_z;
                id_k = row.id;
            }
            None => {
                // Pad slot: random Z_k, Q_k, id_k.
                let mut z_seed = [0u8; 32];
                z_seed.copy_from_slice(&rng[base + 32..base + 64]);
                let mut x_seed = [0u8; 32];
                x_seed.copy_from_slice(&rng[base + 64..base + 96]);

                // Z_k = g^{z_k}; Q_k = g^{x_k}.
                // The doc's Q_k = g^{x_k * r_k} for empty slots is a
                // composition of scalar mults that hacspec doesn't have
                // a primitive for. Indistinguishability from real
                // (Q_k, Z_k) pairs only requires that both look uniform
                // in the group, which a fresh keygen output does.
                let (_, z_pub) = r255_keygen(z_seed);
                z_k = z_pub;
                let (_, q_pub) = r255_keygen(x_seed);
                q_k = q_pub;

                let mut id_buf = [0u8; 16];
                id_buf.copy_from_slice(&rng[base + 96..base + 112]);
                id_k = id_buf;
            }
        }

        // idk_k = KDF(Z_k^{r_k}, NR)
        let zk_rk = r255_dh(&r_k, &z_k);
        let idk_k = kdf(&zk_rk, nr_id);

        // eid_k = AEAD.Enc(idk_k, 0^nl, -, id_k)
        let nonce = [0u8; AEAD_NONCE_LEN];
        let ct = aead_encrypt(&idk_k, &nonce, &[], &id_k);

        let mut eid = [0u8; EID_LEN];
        let copy_len = if ct.len() > EID_LEN { EID_LEN } else { ct.len() };
        eid[..copy_len].copy_from_slice(&ct[..copy_len]);

        items[k] = Some(Challenge { eid, q: q_k });
        k += 1;
    }

    Challenges { items }
}

/// Receiver side of §Step 7 (lines 591-596): for each challenge, attempt
/// AEAD decryption with `tk_k = KDF(Q_k^{sk_R^fetch}, NR)`. Returns the
/// recovered `MessageId`s aligned to the challenge slots (with `None`
/// for slots that didn't decrypt to a 16-byte plaintext).
pub fn receiver_solve_challenges(
    sk_fetch: &FetchSk,
    nr_id: &[u8],
    challenges: &Challenges,
) -> [Option<MessageId>; MAX_MESSAGES] {
    let mut out: [Option<MessageId>; MAX_MESSAGES] = [const { None }; MAX_MESSAGES];

    let mut k = 0;
    while k < MAX_MESSAGES {
        if let Some(chal) = &challenges.items[k] {
            // tk_k = KDF(Q_k^{sk_R^fetch}, NR)
            let qk_skf = r255_dh(&sk_fetch.0, &chal.q);
            let tk_k = kdf(&qk_skf, nr_id);

            let nonce = [0u8; AEAD_NONCE_LEN];
            if let Some(pt) = aead_decrypt(&tk_k, &nonce, &[], &chal.eid) {
                if pt.len() == 16 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&pt);
                    out[k] = Some(id);
                }
            }
        }
        k += 1;
    }
    out
}

/// Server side of §Step 7 (line 600): retrieve the envelope at a given id.
pub fn server_get_message(db: &ServerDb, id: &MessageId) -> Option<Envelope> {
    let mut k = 0;
    while k < MAX_MESSAGES {
        if let Some(row) = &db.rows[k] {
            if row.id == *id {
                return Some(row.envelope.clone());
            }
        }
        k += 1;
    }
    None
}

/// Receiver side of §Step 7 (lines 601-610): trial-decrypt the metadata
/// ciphertext against each available SD-PKE key, then run SD-APKE.AuthDec.
///
/// `sk_apke_options` and `sk_pke_options` are parallel slices: index `i`
/// is one (apke, pke) keybundle. A source provides exactly one; a
/// journalist provides one per ephemeral bundle.
///
/// `sender_allowlist` is `Some` only for source-recipients (line 610):
/// after decryption, the recovered sender APKE pubkey must appear in the
/// allowlist of trusted journalist long-term APKE pubkeys, else discard.
pub fn receiver_decrypt(
    sk_apke_options: &[SdApkeSk],
    sk_pke_options: &[SdPkeSk],
    pk_fetch: &FetchPk,
    nr_id: &[u8],
    envelope: &Envelope,
    sender_allowlist: Option<&[SdApkePk]>,
) -> Option<DecryptedMessage> {
    if sk_apke_options.len() != sk_pke_options.len() {
        return None;
    }

    let pke_ct = crate::sd_pke::SdPkeCt {
        c: envelope.ct_pke.0,
        cp: envelope.ct_pke.1.clone(),
    };

    // Trial-decrypt the metadata ciphertext to find which keybundle
    // applies, and recover the sender's APKE pubkey from the plaintext.
    let mut sender_pk_apke: Option<SdApkePk> = None;
    let mut matching_idx: Option<usize> = None;

    let mut i = 0;
    while i < sk_pke_options.len() {
        if let Some(pt_bytes) = crate::sd_pke::dec(&sk_pke_options[i], &pke_ct) {
            if pt_bytes.len() == crate::wire::SD_PKE_PT_LEN {
                let mut pt_arr = [0u8; crate::wire::SD_PKE_PT_LEN];
                pt_arr.copy_from_slice(&pt_bytes);
                sender_pk_apke = Some(crate::wire::decode_pke_plaintext(&pt_arr));
                matching_idx = Some(i);
                break;
            }
        }
        i += 1;
    }

    let sender_pk_apke = sender_pk_apke?;
    let idx = matching_idx?;

    // SD-APKE.AuthDec
    let pt = crate::sd_apke::auth_dec(
        &sk_apke_options[idx],
        &sender_pk_apke,
        &envelope.ct_apke,
        nr_id,
        &pk_fetch.0,
    )?;

    // Decode pt = pk_S^fetch || pk_S^PKE || m
    if pt.len() != crate::wire::SD_APKE_PT_LEN {
        return None;
    }
    let mut pt_arr = [0u8; crate::wire::SD_APKE_PT_LEN];
    pt_arr.copy_from_slice(&pt);
    let (sender_pk_fetch, sender_pk_pke, msg) =
        crate::wire::decode_apke_plaintext(&pt_arr);

    // Source-only allowlist check (line 610): the recovered sender APKE
    // pubkey must match a trusted journalist long-term APKE pubkey.
    if let Some(allowlist) = sender_allowlist {
        let mut found = false;
        let mut j = 0;
        while j < allowlist.len() {
            if allowlist[j].pk1 == sender_pk_apke.pk1
                && allowlist[j].pk2 == sender_pk_apke.pk2
            {
                found = true;
                break;
            }
            j += 1;
        }
        if !found {
            return None;
        }
    }

    Some(DecryptedMessage {
        msg,
        sender_pk_fetch,
        sender_pk_pke,
    })
}
