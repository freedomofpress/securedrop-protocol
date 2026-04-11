use crate::constants::{LEN_DH_ITEM, LEN_KMID, LEN_XWING_ENCAPS_KEY};
use crate::message::MessagePublicKey;
use crate::metadata;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::DHSharedSecret;
use crate::primitives::x25519::dh_shared_secret;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::x25519::generate_random_scalar;
use crate::primitives::{decrypt_message_id, encrypt_message_id};
use crate::storage::ServerMessageStore;
use crate::{Envelope, FetchResponse, MessageKeyBundle, Plaintext, UserPublic, UserSecret};
use alloc::format;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

// Mock Newsroom ID
const NR_ID: &[u8] = b"MOCK_NEWSROOM_ID";

/// Encrypt a message from a sender to a recipient (step 6).
///
/// Produces an [`Envelope`] containing:
/// - `ct^APKE`: SD-APKE ciphertext (encrypted message)
/// - `ct^PKE`: SD-PKE ciphertext (encrypted sender APKE public key)
/// - `(X, Z)`: hint for privacy-preserving message fetching
pub fn encrypt<R, Sender, Recipient>(
    rng: &mut R,
    sender: &Sender,
    plaintext: &Plaintext,
    recipient: &Recipient,
) -> Envelope
where
    R: RngCore + CryptoRng,
    Sender: UserSecret + ?Sized,
    Recipient: UserPublic + ?Sized,
{
    // spec: sk_S^APKE - sender's long-term APKE private key
    let sk_s = sender.message_auth_key();
    // spec: pk_R^APKE - recipient's APKE public key
    let pk_r = recipient.message_enc_pk();
    // spec: pk_R^fetch
    let pk_r_fetch = recipient.fetch_pk().into_bytes();

    // spec: ct^APKE = SD-APKE.AuthEnc(sk_S^APKE, pk_R^APKE, pt, NR, pk_R^fetch)
    let ct_apke =
        crate::message::auth_enc(rng, sk_s, pk_r, &plaintext.to_bytes(), NR_ID, &pk_r_fetch)
            .expect("SD-APKE AuthEnc failed");

    // Hint (X, Z): X = g^x, Z = (pk_R^fetch)^x for a fresh ephemeral scalar x
    // spec: x (hint_esk), X (hint_epk)
    let (hint_esk, hint_epk) = generate_dh_keypair(rng).expect("DH Keygen (hint) failed");
    // spec: Z = (pk_R^fetch)^x
    let hint_sharedsecret: DHSharedSecret =
        dh_shared_secret(recipient.fetch_pk(), hint_esk.into_bytes())
            .expect("Failed to generate shared secret");

    // spec: pk_S^APKE - sender's long-term APKE public key
    let sender_apke_bytes = sender.message_auth_pk().as_bytes();

    // spec: ct^PKE = SD-PKE.Enc(pk_R^PKE, pk_S^APKE)
    let ct_pke = metadata::encrypt(recipient.message_metadata_pk(), &sender_apke_bytes);

    Envelope {
        ct_apke,                              // spec: ct^APKE
        ct_pke,                               // spec: ct^PKE
        mgdh_pubkey: hint_epk.into_bytes(),   // spec: X = g^x
        mgdh: hint_sharedsecret.into_bytes(), // spec: Z = (pk_R^fetch)^x
    }
}

pub fn decrypt<U: UserSecret + ?Sized>(receiver: &U, envelope: &Envelope) -> Plaintext {
    // Trial-decrypt ct^PKE with each keybundle's metadata private key to find
    // the intended recipient's bundle. There should be exactly 1 result.
    let results: Vec<(&MessageKeyBundle, Vec<u8>)> = receiver
        .keybundles()
        .filter_map(|bundle| {
            metadata::decrypt(bundle.metadata_kp.private_key(), &envelope.ct_pke)
                .ok()
                .map(|m| (bundle, m))
        })
        .collect();

    debug_assert_eq!(results.len(), 1);

    let (bundle, raw_metadata) = results.first().expect("we should find exactly 1 result");

    // spec: pk_S^APKE - reconstruct sender's APKE public key from decrypted metadata
    let sender_pk = MessagePublicKey::from_bytes(raw_metadata)
        .expect("Metadata must contain valid sender APKE key tuple");

    // spec: pk_R^fetch
    let pk_r_fetch = receiver.fetch_keypair().1.into_bytes();

    // spec: pt = SD-APKE.AuthDec(sk_R^APKE, pk_S^APKE, ct^APKE, NR, pk_R^fetch)
    let pt = crate::message::auth_dec(
        bundle.apke.private_key(), // spec: sk_R^APKE
        &sender_pk,                // spec: pk_S^APKE
        &envelope.ct_apke,         // spec: ct^APKE
        NR_ID,                     // spec: NR
        &pk_r_fetch,               // spec: pk_R^fetch
    )
    .expect("SD-APKE AuthDec failed");

    Plaintext::from_bytes(&pt).unwrap()
}

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
pub fn compute_fetch_challenges<R: RngCore + CryptoRng>(
    rng: &mut R,
    store: &ServerMessageStore,
    total_responses: usize,
) -> Vec<FetchResponse> {
    let mut responses = Vec::with_capacity(total_responses);

    // Generate ephemeral (per request) scalar (don't need full keypair)
    let eph_sk = generate_random_scalar(&mut *rng).expect("Want dh scalar");

    for entry in store.keys() {
        let message_id = entry.as_bytes();
        let envelope = store.get(entry).expect("missing message for this uuid");

        // 3-party DH yields shared_secret used to encrypt message_id
        let shared_secret = dh_shared_secret(&DHPublicKey::from_bytes(envelope.mgdh), eph_sk)
            .expect("Need 3-party dh shared secret");
        let enc_mid = encrypt_message_id(&shared_secret.into_bytes(), message_id).unwrap();

        let kmid = enc_mid
            .try_into()
            .expect(&format!("Need {} bytes", LEN_KMID));

        // 2-party DH yields per-request clue (pmgdh) used by intended recipient
        // to compute shared_secret
        let pmgdh = dh_shared_secret(&DHPublicKey::from_bytes(envelope.mgdh_pubkey), eph_sk)
            .expect("Need pmgdh");

        responses.push(FetchResponse {
            enc_id: kmid,
            pmgdh: pmgdh.into_bytes(),
        });

        // Are we done?
        if responses.len() == total_responses {
            break;
        }
    }

    // Pad if needed to return fixed length of responses
    while responses.len() < total_responses {
        let mut pad_kmid: [u8; LEN_KMID] = [0u8; LEN_KMID];
        rng.fill_bytes(&mut pad_kmid);

        let mut pad_pmgdh: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        rng.fill_bytes(&mut pad_pmgdh);

        responses.push(FetchResponse {
            enc_id: pad_kmid,
            pmgdh: pad_pmgdh,
        });
    }
    responses
}

/// Solve fetch challenges (encrypted message IDs) and return array of valid message_ids.
/// TODO: For simplicity, serialize/deserialize is skipped
pub fn solve_fetch_challenges<S: UserSecret>(
    recipient: &S,
    challenges: &[FetchResponse],
) -> Vec<Uuid> {
    let mut message_ids: Vec<Uuid> = Vec::new();

    for chall in challenges.iter() {
        // Compute 3-party DH on the pmgdh
        let maybe_kmid_secret = dh_shared_secret(
            &DHPublicKey::from_bytes(chall.pmgdh),
            recipient.fetch_keypair().0.clone().into_bytes(),
        )
        .expect("Need 3-party DH (scalarmult) on pmgdh");

        // Try decrypting the encrypted message id
        // Convert to UUID (v4) format and add to message ID list on success
        // An error in decryption is fine (may not be a valid message_id), but
        // an error in uuid parsing isn't.
        // TODO: return Result<Vec<Uuid>, Error> instead of panic
        // (will change wasm stuff too so deferring for now)
        decrypt_message_id(&maybe_kmid_secret.into_bytes(), &chall.enc_id)
            .ok()
            .map(|message_id_bytes| {
                Uuid::from_slice(&message_id_bytes)
                    .expect("Need uuid from decrypted message_id_bytes")
            })
            .inspect(|uuid| message_ids.push(*uuid));
    }
    message_ids
}

/// Build plaintext message, including pubkeys (for replies).
/// TODO: only sources need to attach their pubkeys (for replies),
/// but for toy purposes, everyone builds a Plaintext message the same way
pub fn build_message(sender: &impl UserPublic, message: Vec<u8>) -> Plaintext {
    let mut fetch_pk = [0u8; LEN_DH_ITEM];
    fetch_pk.copy_from_slice(&sender.fetch_pk().clone().into_bytes());

    let mut reply_key_pq_hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
    reply_key_pq_hybrid.copy_from_slice(sender.message_metadata_pk().as_bytes());

    Plaintext {
        sender_fetch_key: fetch_pk,
        sender_reply_pubkey_hybrid: reply_key_pq_hybrid,
        msg: message,
    }
}

// Begin unit tests
#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{Journalist, Source};

    use super::*;

    // Test purposes only!
    fn setup_rng() -> impl rand_core::CryptoRng + rand_core::RngCore {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed- is platform supported?");
        ChaCha20Rng::from_seed(seed)
    }

    fn assert_encrypt_decrypt<R: CryptoRng + RngCore>(
        mut rng: R,
        sender_public: &impl UserPublic,
        sender_secret: &impl UserSecret,
        rcvr_public: &impl UserPublic,
        rcvr_secret: &impl UserSecret,
        msg: Vec<u8>,
    ) {
        let pt = build_message(sender_public, msg);

        let envelope = encrypt(&mut rng, sender_secret, &pt, rcvr_public);
        let decrypted = decrypt(rcvr_secret, &envelope);

        let pt_ref = &pt;

        assert_eq!(pt_ref.msg, decrypted.msg);
        assert_eq!(pt_ref.len(), decrypted.to_bytes().len());

        assert_eq!(
            pt_ref.sender_fetch_key,
            sender_secret.fetch_keypair().1.clone().into_bytes()
        );
        assert_eq!(
            &pt_ref.sender_reply_pubkey_hybrid,
            sender_public.message_metadata_pk().as_bytes()
        );
        assert_eq!(
            pt.len(),
            &pt_ref.msg.len() + LEN_DH_ITEM + LEN_XWING_ENCAPS_KEY
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = setup_rng();

        let sender = Source::new(&mut rng);
        let recipient = Journalist::new(&mut rng, 2);

        let msg = b"Encrypt-decrypt-test".to_vec();

        assert_encrypt_decrypt(
            rng,
            &sender.public(),
            &sender,
            &recipient.public(1),
            &recipient,
            msg,
        );
    }

    #[test]
    fn test_encrypt_decrypt_sourcesource() {
        // we don't want this, but it should work anyway
        let mut rng = setup_rng();
        let sender = Source::new(&mut rng);
        let recipient = Source::new(&mut rng);

        assert_encrypt_decrypt(
            rng,
            &sender.public(),
            &sender,
            &recipient.public(),
            &recipient,
            b"Encrypt-decrypt-test".to_vec(),
        );
    }

    #[test]
    fn test_fetch_challenges_roundtrip() {
        let mut rng = setup_rng();

        let source = Source::new(&mut rng);
        let journalist = Journalist::new(&mut rng, 2);

        // pubkey-only capabilities (for receiver)
        let journalist_public = journalist.public(0);

        let msg = b"Fetch this message";
        let plaintext = build_message(&source.public(), msg.to_vec());
        let envelope = encrypt(&mut rng, &source, &plaintext, &journalist_public);

        // On server. TODO: in helper function
        let mut store = ServerMessageStore::new();
        let message_id = uuid::Uuid::new_v4();

        store.insert(message_id, envelope);

        let challenges = compute_fetch_challenges(&mut rng, &store, 2);

        let solved_ids = solve_fetch_challenges(&journalist, &challenges);

        assert_eq!(solved_ids.len(), 1);
        assert_eq!(solved_ids[0], message_id);
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt_challenge() {
        let mut rng = setup_rng();

        let source = Source::new(&mut rng);
        let journalist = Journalist::new(&mut rng, 2);

        let wrong_journalist = Journalist::new(&mut rng, 2);

        // pubkey-only capabilities (for receiver)
        let journalist_public = journalist.public(0);

        let msg = b"Fetch this message";
        let plaintext = build_message(&source.public(), msg.to_vec());
        let envelope = encrypt(&mut rng, &source, &plaintext, &journalist_public);

        // On server. TODO: in helper function
        let mut store = ServerMessageStore::new();
        let message_id = uuid::Uuid::new_v4();

        store.insert(message_id, envelope);

        let challenges = compute_fetch_challenges(&mut rng, &store, 2);

        let solved_ids = solve_fetch_challenges(&journalist, &challenges);

        let solved_ids_miss = solve_fetch_challenges(&wrong_journalist, &challenges);

        assert_eq!(solved_ids.len(), 1);
        assert_eq!(solved_ids[0], message_id);
        assert_eq!(solved_ids_miss.len(), 0);
    }

    #[test]
    fn test_encrypt_decrypt_journalist_only() {
        let mut rng = setup_rng();

        let journalist = Journalist::new(&mut rng, 2);
        let j2 = Journalist::new(&mut rng, 2);

        let msg = "Test message".as_bytes().to_vec();

        assert_encrypt_decrypt(
            rng,
            &journalist.public(0),
            &journalist,
            &j2.public(0),
            &j2,
            msg,
        );
    }
}
