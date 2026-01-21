use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
use crate::primitives::dh_akem::generate_dh_akem_keypair;
use crate::primitives::mlkem::generate_mlkem768_keypair;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::x25519::generate_random_scalar;
use crate::primitives::xwing::generate_xwing_keypair;
use crate::primitives::{decrypt_message_id, encrypt_message_id};
use crate::types::*;
use alloc::{format, vec::Vec};
use anyhow::Error;
use getrandom;
use hpke_rs::libcrux::HpkeLibcrux;
use hpke_rs::{HpkeKeyPair, HpkePrivateKey, HpkePublicKey};
use libcrux_curve25519::hacl::scalarmult;
use libcrux_kem::MlKem768;
use libcrux_traits::kem::owned::Kem;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

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

pub fn hpke_keypair_from_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> HpkeKeyPair {
    HpkeKeyPair::from((sk_bytes, pk_bytes))
}

pub fn hpke_pubkey_from_bytes(pk_bytes: &[u8]) -> HpkePublicKey {
    HpkePublicKey::from(pk_bytes)
}

pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    sender: &dyn User,
    plaintext: &[u8],
    recipient: &dyn User,
    recipient_bundle_index: Option<usize>,
) -> Envelope {
    use hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305;
    use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
    use hpke_rs::hpke_types::KemAlgorithm::{DhKem25519, XWingDraft06};
    use hpke_rs::{Hpke, Mode};

    // TODO: AESGCM instead
    let mut hpke_authenc: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, ChaCha20Poly1305);

    let mut hpke_metadata: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::Base, XWingDraft06, HkdfSha256, ChaCha20Poly1305);

    // In reality, sender will pull a keybundle from the server and verify its signature against the journalist long-term signing key
    let recipient_keybundle = recipient.keybundle(recipient_bundle_index);
    let sender_keys = sender.keybundle(None);

    let recipient_dhakem_pubkey = hpke_pubkey_from_bytes(recipient_keybundle.get_dhakem_pk());

    let sender_hpke_keypair =
        hpke_keypair_from_bytes(sender_keys.get_dhakem_sk(), sender_keys.get_dhakem_pk());

    // Note: Don't need SEED_GEN len randomness (64), just SHARED_SECRET len (32),
    // according to MLK-KEM source code.
    let mut randomness: [u8; LEN_MLKEM_SHAREDSECRET] = [0u8; LEN_MLKEM_SHAREDSECRET];
    rng.fill_bytes(&mut randomness);

    // Calculate PQ PSK - encapsulate to the recipient's key
    let (psk, psk_ct) = MlKem768::encaps(recipient_keybundle.get_pq_kem_psk_pk(), &randomness)
        .expect("PSK encaps failed");

    // Info parameter is pq_psk_encaps_bytes || receiver_fetch_pubkey_bytes
    let mut info = Vec::new();
    info.extend_from_slice(&psk_ct);
    info.extend_from_slice(recipient.get_fetch_pk());

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
            Some(HPKE_PSK_ID),                       // Fixed PSK ID
            Some(sender_hpke_keypair.private_key()), // sender DH-AKEM private key
        )
        .unwrap();

    let mut dhakem_ss_encaps_bytes: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS] =
        [0u8; LEN_DHKEM_SHAREDSECRET_ENCAPS];
    dhakem_ss_encaps_bytes.copy_from_slice(mesage_dhakem_shared_secret_encaps.as_slice());

    // Create mgdh (message clue) with a DH agreement between an ephemeral curve25519 keypair
    // and the recipient's Fetching key
    let eph_sk: [u8; LEN_DH_ITEM] =
        generate_random_scalar(rng).expect("DH keygen (ephemeral fetch) failed!");
    let mut eph_pk: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
    libcrux_curve25519::secret_to_public(&mut eph_pk, &eph_sk);
    let mut mgdh = [0u8; LEN_DH_ITEM];
    let _ = scalarmult(&mut mgdh, &eph_sk, recipient.get_fetch_pk());

    // Serialize sender DH-AKEM pubkey
    let mut sender_pubkey_bytes: [u8; LEN_DHKEM_ENCAPS_KEY] = [0u8; LEN_DHKEM_ENCAPS_KEY];
    sender_pubkey_bytes.copy_from_slice(sender_hpke_keypair.public_key().as_slice());

    // Serialize then encapsulate sender pubkey to recipient metadata key
    // (xwing) in Hpke Base mode:
    // https://www.rfc-editor.org/rfc/rfc9180.html#name-metadata-protection
    // Although we do use a PSK and PSK_ID in the message, we don't need to
    // encrypt the message PSK_ID, because it is a hard-coded string
    let recipient_md_pubkey = hpke_pubkey_from_bytes(recipient_keybundle.get_hybrid_md_pk());

    let (md_ss_encaps_vec, metadata_ciphertext) = hpke_metadata
        .seal(
            &recipient_md_pubkey,
            HPKE_BASE_INFO, // b""
            HPKE_BASE_AAD,  // b""
            &sender_pubkey_bytes,
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
        mgdh_pubkey: eph_pk,
        mgdh: mgdh,
    }
}

pub fn decrypt(receiver: &dyn User, envelope: &Envelope) -> Plaintext {
    use hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305;
    use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
    use hpke_rs::hpke_types::KemAlgorithm::{DhKem25519, XWingDraft06};
    use hpke_rs::{Hpke, Mode};

    let hpke_authenc: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, ChaCha20Poly1305);

    let hpke_base: Hpke<HpkeLibcrux> =
        Hpke::new(Mode::Base, XWingDraft06, HkdfSha256, ChaCha20Poly1305);

    // Receiver needs to know which keybundle to use, so they have to trial decrypt
    // metadata.
    // Explanation of what's happening:
    // - iterate through the user's keybundles, keeping track of the current index
    // - for each keybundle, trial-decrypt the metadata using hpke_base::open
    // - hpke_base::open yields a Result<Plaintext, HpkeError>; filter only the successful ones (Ok), and
    // - collect them and their index, which corresponds to the right keybundle
    // - return the results of that collection.
    // There should be exactly 1 result.
    let results: Vec<(usize, Vec<u8>)> = receiver
        .get_all_keys()
        .iter()
        .enumerate()
        .filter_map(|(i, bundle)| {
            {
                let receiver_metadata_keypair =
                    hpke_keypair_from_bytes(bundle.get_hybrid_md_sk(), bundle.get_hybrid_md_pk());

                let receiver_dhakem_keypair =
                    hpke_keypair_from_bytes(bundle.get_dhakem_sk(), bundle.get_dhakem_pk());

                hpke_base.open(
                    &envelope.metadata_encap,
                    receiver_metadata_keypair.private_key(),
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
    let receiver_keys = receiver.keybundle(Some(*index));

    // kind of silly, but just enforcing length
    let raw_md_bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN] = raw_metadata
        .as_slice()
        .try_into()
        .expect("Need {DH_AKEM_PUBLIC_KEY_LEN} array");

    // hpke keytypes
    let hpke_pubkey_sender = hpke_pubkey_from_bytes(&raw_md_bytes);

    let hpke_receiver_keys =
        hpke_keypair_from_bytes(receiver_keys.get_dhakem_sk(), receiver_keys.get_dhakem_pk());

    // toy (unsafe) parse combined ciphertext
    let combined_ct = CombinedCiphertext::from_bytes(&envelope.cmessage).unwrap();

    // Construct 'info' parameter (authenticated data)
    // Info is c2 || receiver_fetch_pubkey
    let mut info = Vec::new();
    info.extend_from_slice(&combined_ct.message_pqpsk_ss_encap);
    info.extend_from_slice(receiver.get_fetch_pk());

    let psk = MlKem768::decaps(
        &combined_ct.message_pqpsk_ss_encap,
        receiver_keys.get_pq_kem_psk_sk(),
    )
    .unwrap();

    let pt = hpke_authenc
        .open(
            &combined_ct.message_dhakem_ss_encap,
            hpke_receiver_keys.private_key(),
            &info,
            NR_ID, // Recipient supplies NR_ID to decrypt
            &combined_ct.ct_message,
            Some(&psk),
            Some(HPKE_PSK_ID),
            Some(&hpke_pubkey_sender),
        )
        .expect("Decryption failed");

    Plaintext::from_bytes(&pt).unwrap()
}

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid (ServerMessageStore),
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
pub fn compute_fetch_challenges<R: RngCore + CryptoRng>(
    rng: &mut R,
    store: &[ServerMessageStore],
    total_responses: usize,
) -> Vec<FetchResponse> {
    let mut responses = Vec::with_capacity(total_responses);

    // Generate ephemeral (per request) keypair
    let (eph_sk, _eph_pk) = generate_dh_keypair(&mut *rng).expect("Wanted DH keypair");
    let eph_sk_bytes = eph_sk.clone().into_bytes();

    for entry in store.iter() {
        let message_id = &entry.message_id;

        // 3-party DH yields shared_secret used to encrypt message_id
        let mut shared_secret: [u8; LEN_DHKEM_SHARED_SECRET] = [0u8; LEN_DHKEM_SHARED_SECRET];
        let _ = scalarmult(&mut shared_secret, &eph_sk_bytes, &entry.envelope.mgdh);
        let enc_mid = encrypt_message_id(&shared_secret, message_id).unwrap();

        let kmid = enc_mid
            .try_into()
            .expect(&format!("Need {} bytes", LEN_KMID));

        // 2-party DH yields per-request clue (pmgdh) used by intended recipient
        // to compute shared_secret
        let mut pmgdh: [u8; LEN_DHKEM_SHARED_SECRET] = [0u8; LEN_DHKEM_SHARED_SECRET];
        let _ = scalarmult(&mut pmgdh, &eph_sk_bytes, &entry.envelope.mgdh_pubkey);

        responses.push(FetchResponse {
            enc_id: kmid,
            pmgdh: pmgdh,
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
    recipient: &dyn User,
    challenges: Vec<FetchResponse>,
) -> Vec<Vec<u8>> {
    // TODO: Message IDs are probably uuids of type [u8; 16]
    let mut message_ids: Vec<Vec<u8>> = Vec::new();

    for chall in challenges.iter() {
        // Compute 3-party DH on the pmgdh
        let mut maybe_kmid_secret: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        let _ = scalarmult(
            &mut maybe_kmid_secret,
            recipient.get_fetch_sk(),
            &chall.pmgdh,
        );

        // Try using the output for decryption
        let maybe_message_id = decrypt_message_id(&maybe_kmid_secret, &chall.enc_id);

        if let Ok(message_id) = maybe_message_id {
            message_ids.push(message_id);
        }
    }
    message_ids
}

// Test purposes only!
fn setup_rng() -> (impl rand_core::CryptoRng + rand_core::RngCore) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom failed- is platform supported?");
    ChaCha20Rng::from_seed(seed)
}

fn setup_rng_deterministic(seed: [u8; 32]) -> (impl rand_core::CryptoRng + rand_core::RngCore) {
    ChaCha20Rng::from_seed(seed)
}

// Begin unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = setup_rng();

        let sender = Source::new(&mut rng);
        let recipient = Journalist::new(&mut rng, 2);

        let pt = Plaintext {
            sender_reply_pubkey_pq_psk: *sender.keys.get_pq_kem_psk_pk(),
            sender_fetch_key: *sender.get_fetch_pk(),
            sender_reply_pubkey_hybrid: *sender.keys.get_hybrid_md_pk(),
            msg: b"Encrypt-decrypt test".to_vec(),
        };

        let envelope = encrypt(&mut rng, &sender, &pt.to_bytes(), &recipient, None);
        let decrypted = decrypt(&recipient, &envelope);

        assert_eq!(pt.msg, decrypted.msg);
        assert_eq!(pt.sender_fetch_key, *sender.get_fetch_pk());
        assert_eq!(
            pt.sender_reply_pubkey_hybrid,
            *sender.keys.get_hybrid_md_pk()
        );
        assert_eq!(
            pt.sender_reply_pubkey_pq_psk,
            *sender.keys.get_pq_kem_psk_pk()
        );
        assert_eq!(
            pt.len(),
            pt.msg.len() + LEN_DH_ITEM + LEN_MLKEM_ENCAPS_KEY + LEN_XWING_ENCAPS_KEY
        );
    }

    #[test]
    fn test_fetch_challenges_roundtrip() {
        let mut rng = setup_rng();

        let journalist = Journalist::new(&mut rng, 2);
        let source = Source::new(&mut rng);

        let msg = b"Fetch this message";
        let plaintext: Plaintext = Plaintext {
            sender_reply_pubkey_pq_psk: *source.keys.get_pq_kem_psk_pk(),
            sender_reply_pubkey_hybrid: *source.keys.get_hybrid_md_pk(),
            sender_fetch_key: *source.get_fetch_pk(),
            msg: msg.to_vec(),
        };
        let envelope = encrypt(&mut rng, &source, &plaintext.to_bytes(), &journalist, None);

        // On server. TODO: in helper function
        let message_id: [u8; LEN_MESSAGE_ID] = {
            let mut message_id: [u8; LEN_MESSAGE_ID] = [0u8; LEN_MESSAGE_ID];
            rng.fill_bytes(&mut message_id);
            message_id
        };

        let store_entry = ServerMessageStore {
            message_id,
            envelope: envelope,
        };

        let challenges = compute_fetch_challenges(&mut rng, &[store_entry], 2);

        let solved_ids = solve_fetch_challenges(&journalist, challenges);

        assert_eq!(solved_ids.len(), 1);
        assert_eq!(solved_ids[0], message_id);
    }
}
