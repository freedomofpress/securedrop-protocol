use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::DHSharedSecret;
use crate::primitives::x25519::dh_shared_secret;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::x25519::generate_random_scalar;
use crate::primitives::{decrypt_message_id, encrypt_message_id};
use crate::storage::ServerMessageStore;
use crate::types::CombinedCiphertext;
use crate::types::FetchResponse;
use crate::types::Plaintext;
use crate::types::{Envelope, UserPublic, UserSecret};
use alloc::format;
use alloc::vec::Vec;
use hpke_rs::HpkePrivateKey;
use hpke_rs::HpkePublicKey;
use hpke_rs::hpke_types::AeadAlgorithm::Aes256Gcm;
use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
use hpke_rs::hpke_types::KemAlgorithm::{DhKem25519, XWingDraft06};
use hpke_rs::libcrux::HpkeLibcrux;
use hpke_rs::{Hpke, Mode};
use libcrux_kem::MlKem768;
use libcrux_traits::kem::owned::Kem;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

// Mock Newsroom ID
const NR_ID: &[u8] = b"MOCK_NEWSROOM_ID";

const HPKE_PSK_ID: &[u8] = b"PSK_INFO_ID_TAG"; // authpsk only, required by spec
const HPKE_BASE_AAD: &[u8] = b""; // base only; in authpsk mode the NR_ID is supplied
const HPKE_BASE_INFO: &[u8] = b""; // base mode only

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

// https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/#name-encoding-and-sizes
pub const LEN_XWING_ENCAPS_KEY: usize = 1216;
const LEN_XWING_DECAPS_KEY: usize = 32;
const LEN_XWING_SHAREDSECRET_ENCAPS: usize = 1120;
const LEN_XWING_SHAREDSECRET: usize = 32;
const LEN_XWING_RAND_SEED_SIZE: usize = 96;

// Message ID (uuid) and KMID
const LEN_MESSAGE_ID: usize = 16;
// TODO: this will be aes-gcm and use AES GCM TagSize
// TODO: current implementation prepends the nonce to the encrypted message.
// Recheck this when switching implementations.
const LEN_KMID: usize =
    libcrux_chacha20poly1305::TAG_LEN + libcrux_chacha20poly1305::NONCE_LEN + LEN_MESSAGE_ID;

/// Encrypt a message from a sender to a receiver.
/// A sender holds access to UserPublic + UserSecret, i.e. kepyair access.
/// A receiver holds access to UserPublic, i.e. pubkey access.
/// TODO: pass Plaintext instead of &[u8]
pub fn encrypt<Rng, Sndr, Rcvr>(
    rng: &mut Rng,
    sender: &Sndr,
    plaintext: &[u8],
    recipient: &Rcvr,
) -> Envelope
where
    Rng: RngCore + CryptoRng,
    Sndr: UserSecret + ?Sized,
    Rcvr: UserPublic + ?Sized,
{
    let mut hpke_authenc: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, Aes256Gcm);

    let mut hpke_metadata: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::Base, XWingDraft06, HkdfSha256, Aes256Gcm);

    // If sender is Source, they get a recipient bundle from the server
    // and verify it; TODO this is temp implementation
    let recipient_keys = &recipient.message_pks();

    let recipient_dhakem_pubkey = HpkePublicKey::from(recipient_keys.dhakem_pk.as_bytes().to_vec());

    let hpke_sender_key = HpkePrivateKey::from(sender.message_auth_keypair().0.as_bytes().to_vec());

    // Note: Don't need SEED_GEN len randomness (64), just SHARED_SECRET len (32),
    // according to MLK-KEM source code.
    let mut randomness: [u8; LEN_MLKEM_SHAREDSECRET] = [0u8; LEN_MLKEM_SHAREDSECRET];
    rng.fill_bytes(&mut randomness);

    // Calculate PQ PSK - encapsulate to the recipient's key
    let (psk, psk_ct) = MlKem768::encaps(recipient_keys.mlkem_pk.as_bytes(), &randomness)
        .expect("PSK encaps failed");

    // Info parameter is pq_psk_encaps_bytes || receiver_fetch_pubkey_bytes
    let mut info = Vec::new();
    info.extend_from_slice(&psk_ct);
    info.extend_from_slice(&recipient.fetch_pk().clone().into_bytes());

    // TODO: message serialization and format
    // (include any message metadata, the sender serialized XWING pubkey
    // for sending replies, key identifiers, newsroom key/identifier, etc.)
    // At the moment the message being passed here is just the plaintext, but it will have a message structure.

    // HPKE AuthPSK message encryption
    let (mesage_dhakem_shared_secret_encaps, message_ciphertext) = hpke_authenc
        .seal(
            &recipient_dhakem_pubkey,
            // psk_encaps_ct as authenticated (info).
            // In single-shot mode this is how authenticated data is passed:
            // https://www.rfc-editor.org/rfc/rfc9180.html#section-8.1-2
            &info,
            NR_ID, // Newsroom ID is associated data
            plaintext,
            Some(&psk),
            Some(HPKE_PSK_ID),      // Fixed PSK ID
            Some(&hpke_sender_key), // sender DH-AKEM private key
        )
        .unwrap();

    let mut dhakem_ss_encaps_bytes: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS] =
        [0u8; LEN_DHKEM_SHAREDSECRET_ENCAPS];
    dhakem_ss_encaps_bytes.copy_from_slice(mesage_dhakem_shared_secret_encaps.as_slice());

    // Create mgdh (message clue) with a DH agreement between an ephemeral curve25519 keypair
    // and the recipient's Fetching key
    let (hint_esk, hint_epk) = generate_dh_keypair(rng).expect("Dh Keygen (fetch) failed");

    let hint_sharedsecret: DHSharedSecret =
        dh_shared_secret(recipient.fetch_pk(), hint_esk.into_bytes())
            .expect("Failed to generate shared secret");

    // Serialize sender DH-AKEM pubkey
    let sender_pubkey_bytes = sender.message_auth_keypair().1.as_bytes();

    // Serialize then encapsulate sender pubkey to recipient metadata key
    // (xwing) in Hpke Base mode:
    // https://www.rfc-editor.org/rfc/rfc9180.html#name-metadata-protection
    // Although we do use a PSK and PSK_ID in the message, we don't need to
    // encrypt the message PSK_ID, because it is a hard-coded string
    let recipient_md_pubkey = HpkePublicKey::from(recipient_keys.xwing_pk.clone());

    let (md_ss_encaps_vec, metadata_ciphertext) = hpke_metadata
        .seal(
            &recipient_md_pubkey,
            HPKE_BASE_INFO, // b""
            HPKE_BASE_AAD,  // b""
            sender_pubkey_bytes,
            None,
            None,
            None,
        )
        .expect("Expected Hpke.BaseMode sealed ciphertext");

    let metadata_ss_encaps: [u8; LEN_XWING_SHAREDSECRET_ENCAPS] =
        md_ss_encaps_vec.try_into().expect(&format!(
            "Need {} byte encapsulated shared secret",
            LEN_XWING_SHAREDSECRET_ENCAPS
        ));

    let cmessage = CombinedCiphertext {
        message_dhakem_ss_encap: dhakem_ss_encaps_bytes,
        message_pqpsk_ss_encap: psk_ct,
        ct_message: message_ciphertext,
    };

    Envelope {
        // authenc ciphertext
        cmessage: cmessage.to_bytes(),

        // sender pubkey ciphertext
        cmetadata: metadata_ciphertext,

        // sender pubkey ss encaps
        metadata_encap: metadata_ss_encaps,

        // clue stuff
        mgdh_pubkey: hint_epk.into_bytes(),
        mgdh: hint_sharedsecret.into_bytes(),
    }
}

pub fn decrypt<U: UserSecret + ?Sized>(receiver: &U, envelope: &Envelope) -> Plaintext {
    use hpke_rs::hpke_types::AeadAlgorithm::Aes256Gcm;
    use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
    use hpke_rs::hpke_types::KemAlgorithm::{DhKem25519, XWingDraft06};
    use hpke_rs::{Hpke, Mode};

    let hpke_authenc: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, Aes256Gcm);

    let hpke_base: Hpke<HpkeLibcrux> = Hpke::new(Mode::Base, XWingDraft06, HkdfSha256, Aes256Gcm);

    // Receiver needs to know which keybundle to use, so they have to trial decrypt
    // metadata.
    // Explanation of what's happening:
    // - for each keybundle in range (0..len), trial-decrypt the metadata using hpke_base::open (yields Result<Plaintext, HpkeError>)
    // - filter only the successful ones (Ok) and
    // - collect the successful decryptions (Vec<u8>) and their index, which corresponds to the correct keybundle
    // - return the results of that collection.
    // There should be exactly 1 result.
    let results: Vec<(usize, Vec<u8>)> = (0..receiver.num_bundles())
        .filter_map(|i| {
            {
                let md_key = receiver.message_bundle_keypairs(i).2.0.clone().into();

                hpke_base.open(
                    &envelope.metadata_encap,
                    &md_key,
                    HPKE_BASE_INFO,
                    HPKE_BASE_AAD,
                    &envelope.cmetadata,
                    None,
                    None,
                    None,
                )
            }
            .ok()
            .map(|decrypted_metadata| (i, decrypted_metadata))
        })
        .collect();

    // Sanity
    assert_eq!(results.len(), 1);

    let (index, raw_metadata) = results.first().unwrap();

    // Now we know which keybundle to use
    // (the final item in the tuple was already used to decrypt metadata)
    let (receiver_dhakem, receiver_mlkem_sk, _) = receiver.message_bundle_keypairs(*index);

    // kind of silly, but just enforcing length
    let raw_md_bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN] = raw_metadata
        .as_slice()
        .try_into()
        .expect("Need {DH_AKEM_PUBLIC_KEY_LEN} array");

    let sender_dhakem: HpkePublicKey = DhAkemPublicKey::from_bytes(raw_md_bytes).into();

    let receiver_dhakem: HpkePrivateKey = receiver_dhakem.0.clone().into();

    // toy (unsafe) parse combined ciphertext
    let combined_ct = CombinedCiphertext::from_bytes(&envelope.cmessage).unwrap();

    // Construct 'info' parameter (authenticated data)
    // Info is c2 || receiver_fetch_pubkey
    let mut info = Vec::new();
    info.extend_from_slice(&combined_ct.message_pqpsk_ss_encap);
    info.extend_from_slice(&receiver.fetch_keypair().1.clone().into_bytes());

    let psk = MlKem768::decaps(
        &combined_ct.message_pqpsk_ss_encap,
        receiver_mlkem_sk.0.as_bytes(),
    )
    .unwrap();

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
pub fn solve_fetch_challenges(
    recipient: &dyn UserSecret,
    challenges: Vec<FetchResponse>,
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
    let mut reply_key_pq_psk = [0u8; LEN_MLKEM_ENCAPS_KEY];
    reply_key_pq_psk.copy_from_slice(sender.message_pks().mlkem_pk.as_bytes());

    let mut fetch_pk = [0u8; LEN_DH_ITEM];
    fetch_pk.copy_from_slice(&sender.fetch_pk().clone().into_bytes());

    let mut reply_key_pq_hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
    reply_key_pq_hybrid.copy_from_slice(sender.message_pks().xwing_pk.as_bytes());

    Plaintext {
        sender_reply_pubkey_pq_psk: reply_key_pq_psk,
        sender_fetch_key: fetch_pk,
        sender_reply_pubkey_hybrid: reply_key_pq_hybrid,
        msg: message,
    }
}

// Begin unit tests
#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::types::{Journalist, Source};

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

        let envelope = encrypt(&mut rng, sender_secret, &pt.to_bytes(), rcvr_public);
        let decrypted = decrypt(rcvr_secret, &envelope);

        assert_eq!(pt.msg, decrypted.msg);
        assert_eq!(pt.to_bytes().len(), decrypted.to_bytes().len());

        assert_eq!(
            pt.sender_fetch_key,
            sender_secret.fetch_keypair().1.clone().into_bytes()
        );
        assert_eq!(
            &pt.sender_reply_pubkey_hybrid,
            sender_public.message_pks().xwing_pk.as_bytes()
        );
        assert_eq!(
            &pt.sender_reply_pubkey_pq_psk,
            sender_public.message_pks().mlkem_pk.as_bytes()
        );
        assert_eq!(
            pt.len(),
            pt.msg.len() + LEN_DH_ITEM + LEN_MLKEM_ENCAPS_KEY + LEN_XWING_ENCAPS_KEY
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
    fn test_encrypt_decrypt_journalist_onekey() {
        let mut rng = setup_rng();
        let sender = Source::new(&mut rng);
        let recipient = Journalist::new(&mut rng, 1);

        assert_encrypt_decrypt(
            rng,
            &sender.public(),
            &sender,
            &recipient.public(0),
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
        let envelope = encrypt(&mut rng, &source, &plaintext.to_bytes(), &journalist_public);

        // On server. TODO: in helper function
        let mut store = ServerMessageStore::new();
        let message_id = uuid::Uuid::new_v4();

        store.insert(message_id, envelope);

        let challenges = compute_fetch_challenges(&mut rng, &store, 2);

        let solved_ids = solve_fetch_challenges(&journalist, challenges);

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
        let envelope = encrypt(&mut rng, &source, &plaintext.to_bytes(), &journalist_public);

        // On server. TODO: in helper function
        let mut store = ServerMessageStore::new();
        let message_id = uuid::Uuid::new_v4();

        store.insert(message_id, envelope);

        let challenges = compute_fetch_challenges(&mut rng, &store, 2);

        let chall = challenges.clone();

        let solved_ids = solve_fetch_challenges(&journalist, chall);

        let solved_ids_miss = solve_fetch_challenges(&wrong_journalist, challenges);

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
