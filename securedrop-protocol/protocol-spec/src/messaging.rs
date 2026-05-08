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

// ===========================================================================
// §Step 5: wire types
// ===========================================================================

/// One row of `pks` from §Step 5 (line 451).
pub struct PkBundleEntry {
    pub vk_j_sig: SigVk,
    pub pk_j_apke_e: SdApkePk,
    pub pk_j_pke_e: SdPkePk,
    pub pk_j_fetch: FetchPk,
    pub pk_j_apke: SdApkePk,
}

/// One row of `sigs` from §Step 5 (line 452).
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
pub struct ServerRow {
    pub id: MessageId,
    pub envelope: Envelope,
}

/// Server message database, fixed-size per the doc's pad-to-MAX_MESSAGES
/// requirement (line 614, line 672).
pub struct ServerDb {
    pub rows: [Option<ServerRow>; MAX_MESSAGES],
}

// ===========================================================================
// §Step 7: wire types
// ===========================================================================

/// Per-message challenge `(eid_k, Q_k)` (§Step 7, line 589).
pub struct Challenge {
    /// `eid_k = AEAD.Enc(idk_k, 0^nl, -, id_k)` (§line 588).
    pub eid: [u8; 16 + AEAD_NONCE_LEN + AEAD_TAG_LEN],
    /// `Q_k = X_k^{r_k}` (§line 580).
    pub q: R255Point,
}

/// Server's response to `RequestMessages` (§Step 7).
pub struct Challenges {
    pub items: [Option<Challenge>; MAX_MESSAGES],
}

/// Result of decrypting an envelope (§Step 7, line 608).
/// `pt = m || pk_S^fetch || pk_S^PKE`.
pub struct DecryptedMessage {
    pub msg: Vec<u8>,
    pub sender_pk_fetch: FetchPk,
    pub sender_pk_pke: SdPkePk,
}

// ===========================================================================
// §Step 5: signature-chain verification
// ===========================================================================

/// Server side of §Step 5 (lines 450-453): for each journalist, select
/// one random key bundle, return `(pks, sigs)`, and remove the consumed
/// bundle from storage.
pub fn server_select_keys(
    _db: ServerDb,
    _ephemerals_per_j: &[Vec<JournalistEphemeral>; N_JOURNALISTS],
    _journalists: &[Option<JournalistLongTerm>; N_JOURNALISTS],
    _rng: [u8; 32],
) -> (KeysResponse, ServerDb) {
    unimplemented!()
}

/// Sender side of §Step 5 (lines 455-457): verify all three signature
/// chains. Aborts on the first failure.
pub fn sender_verify_keys(
    _vk_nr: &SigVk,
    _resp: &KeysResponse,
) -> Result<(), AbortReason> {
    unimplemented!()
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
/// the Ristretto255 hint keypair generation.
pub fn sender_encrypt_for_recipient(
    _sender_sk_apke: &SdApkeSk,
    _sender_pk_apke: &SdApkePk,
    _sender_pk_fetch: &FetchPk,
    _sender_pk_pke: &SdPkePk,
    _recipient: &PkBundleEntry,
    _nr_id: &[u8],
    _message: &[u8],
    _randomness: [u8; 256],
) -> Envelope {
    unimplemented!()
}

/// Server side of §Step 6 (lines 544-545): generate a fresh message ID,
/// store the row, return updated database.
pub fn server_store_message(
    _db: ServerDb,
    _envelope: Envelope,
    _id_seed: [u8; 16],
) -> ServerDb {
    unimplemented!()
}

// ===========================================================================
// §Step 7: fetch and decrypt
// ===========================================================================

/// Server side of §Step 7 (lines 577-589): construct the `MAX_MESSAGES`
/// challenges, padding with random values for empty slots (lines
/// 581-588). Constant-time per the requirement at line 614.
pub fn server_compute_challenges(
    _db: &ServerDb,
    _nr_id: &[u8],
    _rng: &[u8],
) -> Challenges {
    unimplemented!()
}

/// Receiver side of §Step 7 (lines 591-596): for each challenge, attempt
/// decryption with the receiver's fetch key. Returns the recovered
/// `MessageId`s (with `None` slots for failed challenges).
pub fn receiver_solve_challenges(
    _sk_fetch: &FetchSk,
    _nr_id: &[u8],
    _challenges: &Challenges,
) -> [Option<MessageId>; MAX_MESSAGES] {
    unimplemented!()
}

/// Server side of §Step 7 (line 600): retrieve the envelope at a given id.
pub fn server_get_message(_db: &ServerDb, _id: &MessageId) -> Option<Envelope> {
    unimplemented!()
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
    _sk_apke_options: &[SdApkeSk],
    _sk_pke_options: &[SdPkeSk],
    _pk_fetch: &FetchPk,
    _nr_id: &[u8],
    _envelope: &Envelope,
    _sender_allowlist: Option<&[SdApkePk]>,
) -> Option<DecryptedMessage> {
    unimplemented!()
}
