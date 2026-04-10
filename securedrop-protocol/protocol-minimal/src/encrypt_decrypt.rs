use crate::constants::LEN_XWING_ENCAPS_KEY;
use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::DHSharedSecret;
use crate::primitives::x25519::dh_shared_secret;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::x25519::generate_random_scalar;
use crate::primitives::{decrypt_message_id, encrypt_message_id};
use crate::storage::ServerMessageStore;
use crate::{
    CombinedCiphertext, Envelope, FetchResponse, MessageKeyBundle, Plaintext, UserPublic,
    UserSecret,
};
use alloc::format;
use alloc::vec::Vec;
use hpke_rs::HpkePrivateKey;
use hpke_rs::HpkePublicKey;
use hpke_rs::hpke_types::AeadAlgorithm::Aes256Gcm;
use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
use hpke_rs::hpke_types::KemAlgorithm::DhKem25519;
use hpke_rs::libcrux::HpkeLibcrux;
use hpke_rs::{Hpke, Mode};
use libcrux_kem::MlKem768;
use libcrux_traits::kem::owned::Kem;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

// Mock Newsroom ID
const NR_ID: &[u8] = b"MOCK_NEWSROOM_ID";

const HPKE_PSK_ID: &[u8] = b"PSK_INFO_ID_TAG"; // authpsk only, required by spec

// Key lengths
const LEN_DHKEM_ENCAPS_KEY: usize = libcrux_curve25519::EK_LEN;
const LEN_DHKEM_DECAPS_KEY: usize = libcrux_curve25519::DK_LEN;
const LEN_DHKEM_SHAREDSECRET_ENCAPS: usize = libcrux_curve25519::SS_LEN;
const LEN_DHKEM_SHARED_SECRET: usize = libcrux_curve25519::SS_LEN;
pub const LEN_DH_ITEM: usize = LEN_DHKEM_DECAPS_KEY;

// https://openquantumsafe.org/liboqs/algorithms/kem/ml-kem.html
// todo, source from crates instead of hardcoding
pub const LEN_MLKEM_ENCAPS_KEY: usize = 1184;
const LEN_MLKEM_DECAPS_KEY: usize = 2400;
const LEN_MLKEM_SHAREDSECRET_ENCAPS: usize = 1088;
const LEN_MLKEM_SHAREDSECRET: usize = 32;
const LEN_MLKEM_RAND_SEED_SIZE: usize = 64;

// Message ID (uuid) and KMID
const LEN_MESSAGE_ID: usize = 16;
// TODO: this will be aes-gcm and use AES GCM TagSize
// TODO: current implementation prepends the nonce to the encrypted message.
// Recheck this when switching implementations.
const LEN_KMID: usize =
    libcrux_chacha20poly1305::TAG_LEN + libcrux_chacha20poly1305::NONCE_LEN + LEN_MESSAGE_ID;

/// Encrypt a message from a sender to a receiver.
/// A sender holds access to UserPublic + UserSecret, i.e. keypair access.
/// A receiver holds access to UserPublic, i.e. pubkey access.
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
    let mut hpke_authenc: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, Aes256Gcm);

    // spec: pk_R^AKEM: the DH-AKEM component of the recipient's APKE key bundle
    let recipient_message_enc_dhakem_pub = recipient.message_enc_pk().clone().into();
    // spec: sk_S^AKEM: the DH-AKEM component of the sender's long-term APKE key tuple (sk_S^APKE)
    let hpke_sender_key = sender.message_auth_keypair().0.clone().into();

    // Note: Don't need SEED_GEN len randomness (64), just SHARED_SECRET len (32),
    // according to MLK-KEM source code.
    let mut randomness: [u8; LEN_MLKEM_SHAREDSECRET] = [0u8; LEN_MLKEM_SHAREDSECRET];
    rng.fill_bytes(&mut randomness);

    // Calculate PQ PSK - encapsulate to the recipient's key
    let (psk, psk_ct) = MlKem768::encaps(&recipient.message_psk_pk().as_bytes(), &randomness)
        .expect("PSK encaps failed");

    // Info parameter is pq_psk_encaps_bytes || receiver_fetch_pubkey_bytes
    // spec: SD-APKE AuthEnc sets info = c2 || pk_R^fetch
    let mut info = Vec::new();
    info.extend_from_slice(&psk_ct);
    info.extend_from_slice(&recipient.fetch_pk().clone().into_bytes());

    // TODO: message serialization and format
    // (include any message metadata, the sender serialized XWING pubkey
    // for sending replies, key identifiers, newsroom key/identifier, etc.)
    // At the moment the message being passed here is just the plaintext, but it will have a message structure.

    // spec: ct^APKE = SD-APKE.AuthEnc(sk_S^APKE, pk_R^APKE, pt, NR_ID, pk_R^fetch)
    // HPKE AuthPSK message encryption
    let (message_dhakem_shared_secret_encaps, message_ciphertext) = hpke_authenc
        .seal(
            &recipient_message_enc_dhakem_pub,
            // psk_encaps_ct as authenticated (info).
            // In single-shot mode this is how authenticated data is passed:
            // https://www.rfc-editor.org/rfc/rfc9180.html#section-8.1-2
            &info,
            NR_ID, // Newsroom ID is associated data
            &plaintext.to_bytes(),
            Some(&psk),
            Some(HPKE_PSK_ID),      // Fixed PSK ID
            Some(&hpke_sender_key), // sender DH-AKEM private key
        )
        .unwrap();

    let mut dhakem_ss_encaps_bytes: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS] =
        [0u8; LEN_DHKEM_SHAREDSECRET_ENCAPS];
    dhakem_ss_encaps_bytes.copy_from_slice(message_dhakem_shared_secret_encaps.as_slice());

    // Hint (X, Z): X = g^x, Z = (pk_R^fetch)^x for a fresh ephemeral scalar x
    // Create mgdh (message clue) with a DH agreement between an ephemeral curve25519 keypair
    // and the recipient's Fetching key
    // spec: `hint_esk` = x
    // spec: `hint_epk` = X
    let (hint_esk, hint_epk) = generate_dh_keypair(rng).expect("Dh Keygen (fetch) failed");

    // spec: `hint_sharedsecret` = Z = (pk_R^fetch)^x
    let hint_sharedsecret: DHSharedSecret =
        dh_shared_secret(recipient.fetch_pk(), hint_esk.into_bytes())
            .expect("Failed to generate shared secret");

    // Serialize the full sender APKE public key tuple: pk_S^AKEM || pk_S^PQ
    let mut sender_apke_bytes = Vec::new();
    sender_apke_bytes.extend_from_slice(sender.message_auth_keypair().1.as_bytes()); // pk_S^AKEM (DH-AKEM)
    sender_apke_bytes.extend_from_slice(sender.message_psk_pk().as_bytes()); // pk_S^PQ (ML-KEM)

    // spec: ct^PKE = SD-PKE.Enc(pk_R^PKE, pk_S^APKE)
    let ct_pke = recipient.message_metadata_pk().encrypt(&sender_apke_bytes);

    let cmessage = CombinedCiphertext {
        message_dhakem_ss_encap: dhakem_ss_encaps_bytes,
        message_pqpsk_ss_encap: psk_ct,
        ct_message: message_ciphertext,
    };
    // TODO: define C_S as in the spec

    // Send (C_S, X, Z) to server
    Envelope {
        cmessage: cmessage.to_bytes(),        // ct^APKE
        ct_pke,                               // ct^PKE
        mgdh_pubkey: hint_epk.into_bytes(),   // X = g^x
        mgdh: hint_sharedsecret.into_bytes(), // Z = (pk_R^fetch)^x
    }
}

pub fn decrypt<U: UserSecret + ?Sized>(receiver: &U, envelope: &Envelope) -> Plaintext {
    let hpke_authenc: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, Aes256Gcm);

    // Trial-decrypt ct^PKE with each keybundle's metadata private key to find
    // the intended recipient's bundle. There should be exactly 1 result.
    let results: Vec<(&MessageKeyBundle, Vec<u8>)> = receiver
        .keybundles()
        .filter_map(|bundle| {
            bundle
                .metadata_kp
                .private_key()
                .decrypt(&envelope.ct_pke)
                .ok()
                .map(|m| (bundle, m))
        })
        .collect();

    // Sanity check
    debug_assert_eq!(results.len(), 1);

    // Unpack the results of the trial decryption, yielding metadata and correct decryption keys
    let (bundle, raw_metadata) = results.first().unwrap();
    let receiver_dhakem: &HpkePrivateKey = &bundle.dh_akem.sk.clone().into();
    let receiver_pqkem_bytes: &[u8; LEN_MLKEM_DECAPS_KEY] = bundle.mlkem.sk.as_bytes();

    // we should have the full APKE public key tuple: pk_S^AKEM (DH-AKEM) || pk_S^PQ (ML-KEM)
    assert_eq!(
        raw_metadata.len(),
        DH_AKEM_PUBLIC_KEY_LEN + LEN_MLKEM_ENCAPS_KEY,
        "Metadata must contain the full sender APKE key tuple"
    );
    let sender_dhakem_bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN] = raw_metadata[..DH_AKEM_PUBLIC_KEY_LEN]
        .try_into()
        .expect("Need DH_AKEM_PUBLIC_KEY_LEN bytes for sender DH-AKEM key");
    let _sender_mlkem_bytes: [u8; LEN_MLKEM_ENCAPS_KEY] = raw_metadata[DH_AKEM_PUBLIC_KEY_LEN..]
        .try_into()
        .expect("Need LEN_MLKEM_ENCAPS_KEY bytes for sender ML-KEM key");

    let sender_dhakem: HpkePublicKey = DhAkemPublicKey::from_bytes(sender_dhakem_bytes).into();

    // toy (unsafe) parse combined ciphertext
    let combined_ct = CombinedCiphertext::from_bytes(&envelope.cmessage).unwrap();

    // Construct 'info' parameter (authenticated data)
    // Info is c2 || receiver_fetch_pubkey
    let mut info = Vec::new();
    info.extend_from_slice(&combined_ct.message_pqpsk_ss_encap);
    info.extend_from_slice(&receiver.fetch_keypair().1.clone().into_bytes());

    let psk = MlKem768::decaps(&combined_ct.message_pqpsk_ss_encap, receiver_pqkem_bytes).unwrap();

    let pt = hpke_authenc
        .open(
            &combined_ct.message_dhakem_ss_encap,
            &receiver_dhakem,
            &info,
            NR_ID, // Recipient supplies NR_ID to decrypt
            &combined_ct.ct_message,
            Some(&psk),
            Some(HPKE_PSK_ID),
            Some(&sender_dhakem),
        )
        .expect("Decryption failed");

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
    use libcrux_kem::MlKemKeyPair;
    use proptest::prelude::Rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        DhAkemKeyPair, Journalist, KeyBundlePublic, KeyPair, MlKem768KeyPair, Source,
        primitives::{
            dh_akem::DhAkemPrivateKey,
            generate_dh_akem_keypair, generate_mlkem768_keypair,
            mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey},
            x25519::DHPrivateKey,
        },
        private,
    };

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
