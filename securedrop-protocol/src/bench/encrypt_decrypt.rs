use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
use crate::primitives::dh_akem::generate_dh_akem_keypair;
use crate::primitives::mlkem::generate_mlkem768_keypair;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::x25519::generate_random_scalar;
use crate::primitives::xwing::generate_xwing_keypair;
use crate::primitives::{decrypt_message_id, encrypt_message_id};
use alloc::{format, vec::Vec};
use anyhow::Error;
use getrandom;
use hpke_rs::libcrux::HpkeLibcrux;
use hpke_rs::{HpkeKeyPair, HpkePrivateKey, HpkePublicKey};
use libcrux_curve25519::hacl::scalarmult;
use libcrux_kem::MlKem768;
use libcrux_traits::kem::secrets::Kem;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

const HPKE_PSK_ID: &[u8] = b"PSK_INFO_ID_TAG"; // authpsk only, required by spec
const HPKE_AAD: &[u8] = b""; // base and authpsk
const HPKE_BASE_INFO: &[u8] = b""; // base mode only

// Key lengths
const LEN_DHKEM_ENCAPS_KEY: usize = libcrux_curve25519::EK_LEN;
const LEN_DHKEM_DECAPS_KEY: usize = libcrux_curve25519::DK_LEN;
const LEN_DHKEM_SHAREDSECRET_ENCAPS: usize = libcrux_curve25519::SS_LEN;
const LEN_DHKEM_SHARED_SECRET: usize = libcrux_curve25519::SS_LEN;
const LEN_DH_ITEM: usize = LEN_DHKEM_DECAPS_KEY;

// https://openquantumsafe.org/liboqs/algorithms/kem/ml-kem.html
// todo, source from crates instead of hardcoding
const LEN_MLKEM_ENCAPS_KEY: usize = 1184;
const LEN_MLKEM_DECAPS_KEY: usize = 2400;
const LEN_MLKEM_SHAREDSECRET_ENCAPS: usize = 1088;
const LEN_MLKEM_SHAREDSECRET: usize = 32;
const LEN_MLKEM_RAND_SEED_SIZE: usize = 64;

// https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/#name-encoding-and-sizes
const LEN_XWING_ENCAPS_KEY: usize = 1216;
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

#[derive(Debug, Clone)]
pub struct CombinedCiphertext {
    // authenc message ciphertext
    ct_message: Vec<u8>,

    // dh-akem ss encaps (needed to decrypt message)
    message_dhakem_ss_encap: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS],

    // pq psk encap (needed to decaps psk)
    // also passed as `info` param during hpke.authopen
    message_pqpsk_ss_encap: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS],
}

impl CombinedCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Store fixed-size arrays
        buf.extend_from_slice(&self.message_dhakem_ss_encap);
        buf.extend_from_slice(&self.message_pqpsk_ss_encap);

        // Store cmessage bytes
        buf.extend_from_slice(&self.ct_message);

        buf
    }

    pub fn len(&self) -> usize {
        self.to_bytes().len()
    }

    // TOY ONLY
    pub fn from_bytes(ct_bytes: &Vec<u8>) -> Result<Self, Error> {
        let mut dhakem_ss_encaps: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS] =
            [0u8; LEN_DHKEM_SHAREDSECRET_ENCAPS];

        let mut pqpsk_ss_encaps: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS] =
            [0u8; LEN_MLKEM_SHAREDSECRET_ENCAPS];

        dhakem_ss_encaps.copy_from_slice(&ct_bytes[0..LEN_DHKEM_SHAREDSECRET_ENCAPS]);

        pqpsk_ss_encaps.copy_from_slice(
            &ct_bytes[LEN_DHKEM_SHAREDSECRET_ENCAPS
                ..LEN_DHKEM_SHAREDSECRET_ENCAPS + LEN_MLKEM_SHAREDSECRET_ENCAPS],
        );

        let cmessage: Vec<u8> =
            ct_bytes[LEN_DHKEM_SHAREDSECRET_ENCAPS + LEN_MLKEM_SHAREDSECRET_ENCAPS..].to_vec();

        Ok(CombinedCiphertext {
            ct_message: (cmessage),
            message_dhakem_ss_encap: dhakem_ss_encaps,
            message_pqpsk_ss_encap: pqpsk_ss_encaps,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Envelope {
    // (message_ciphertext || message_dhakem_ss_encap || msg_psk_ss_encap)
    // see CombinedCiphertext
    cmessage: Vec<u8>,

    // baseenc "metadata", aka sender pubkey
    cmetadata: Vec<u8>,

    // "metadata" encaps shared secret
    metadata_encap: [u8; LEN_XWING_SHAREDSECRET_ENCAPS],

    // clue material
    mgdh_pubkey: [u8; LEN_DH_ITEM],
    mgdh: [u8; LEN_DH_ITEM],
}

// TODO: plaintext structure/types
#[derive(Debug)]
pub struct Plaintext {
    // todo: this is an ID instead of a pubkey, it's attached already
    recipient_pubkey_dhakem: Option<Vec<u8>>,

    sender_reply_pubkey_dhakem: Option<Vec<u8>>,
    sender_reply_pubkey_pq_psk: Option<Vec<u8>>,
    sender_reply_pubkey_hybrid: Option<Vec<u8>>,
    sender_fetch_key: Option<Vec<u8>>,

    msg: Vec<u8>,
}

/// Represent stored ciphertexts on the server
pub struct ServerMessageStore {
    message_id: [u8; LEN_MESSAGE_ID],
    envelope: Envelope,
}

pub struct FetchResponse {
    enc_id: [u8; LEN_KMID],   // aka kmid
    pmgdh: [u8; LEN_DH_ITEM], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; LEN_DH_ITEM]) -> Self {
        Self {
            enc_id: enc_id,
            pmgdh: pmgdh,
        }
    }
}

impl Plaintext {
    pub fn as_bytes(&self) -> &[u8] {
        // TODO: serialize in order including keys
        &self.msg
    }

    pub fn len(&self) -> usize {
        self.msg.len()
    }

    pub fn into_bytes(self) -> alloc::vec::Vec<u8> {
        self.msg
    }
}

impl Envelope {
    // Used for benchmarks - see wasm_bindgen
    pub fn size_hint(&self) -> usize {
        self.cmessage.len() + self.cmetadata.len()
    }

    pub fn cmessage_len(&self) -> usize {
        self.cmessage.len()
    }

    // sender dh-akem pubkey bytes
    pub fn cmetadata_len(&self) -> usize {
        self.cmetadata.len()
    }
}

impl ServerMessageStore {
    pub fn new(message_id: [u8; 16], envelope: Envelope) -> Self {
        Self {
            message_id,
            envelope,
        }
    }

    pub fn message_id(&self) -> [u8; 16] {
        self.message_id
    }

    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }
}

// Keys used for individual messages
pub struct KeyBundle {
    dhakem_sk: [u8; LEN_DH_ITEM],
    pub dhakem_pk: [u8; LEN_DH_ITEM],

    pq_kem_psk_sk: [u8; LEN_MLKEM_DECAPS_KEY],
    pub pq_kem_psk_pk: [u8; LEN_MLKEM_ENCAPS_KEY],

    hybrid_md_sk: [u8; LEN_XWING_DECAPS_KEY],
    pub hybrid_md_pk: [u8; LEN_XWING_ENCAPS_KEY],
}

impl KeyBundle {
    // msg enc classical
    fn get_dhakem_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.dhakem_sk
    }
    fn get_dhakem_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.dhakem_pk
    }

    // msg enc pq psk
    fn get_pq_kem_psk_pk(&self) -> &[u8; LEN_MLKEM_ENCAPS_KEY] {
        &self.pq_kem_psk_pk
    }

    fn get_pq_kem_psk_sk(&self) -> &[u8; LEN_MLKEM_DECAPS_KEY] {
        &self.pq_kem_psk_sk
    }

    // md enc hybrid
    fn get_hybrid_md_pk(&self) -> &[u8; LEN_XWING_ENCAPS_KEY] {
        &self.hybrid_md_pk
    }

    fn get_hybrid_md_sk(&self) -> &[u8; LEN_XWING_DECAPS_KEY] {
        &self.hybrid_md_sk
    }
}

pub trait User {
    fn keybundle(&self, index: Option<usize>) -> &KeyBundle;
    // fetch classical
    fn get_fetch_sk(&self) -> &[u8; LEN_DH_ITEM];
    fn get_fetch_pk(&self) -> &[u8; LEN_DH_ITEM];

    // ~only for journalists, here for simplicity
    fn get_all_keys(&self) -> &[KeyBundle];
}

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
            &psk_ct,
            HPKE_AAD,
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

    // Serialize sender Dh-AKEM pubkey for Metadata
    let mut sender_pubkey_bytes: [u8; LEN_DHKEM_ENCAPS_KEY] = [0u8; LEN_DHKEM_ENCAPS_KEY];
    sender_pubkey_bytes.copy_from_slice(sender_hpke_keypair.public_key().as_slice());

    // Serialize then encrypt sender pubkey metadata key (xwing) and Hpke Base mode:
    // https://www.rfc-editor.org/rfc/rfc9180.html#name-metadata-protection
    // Although we do use a PSK and PSK_ID in the message, we don't need to
    // encrypt the message PSK_ID, because it is a hard-coded string
    let recipient_md_pubkey = hpke_pubkey_from_bytes(recipient_keybundle.get_hybrid_md_pk());

    let (md_ss_encaps_vec, metadata_ciphertext) = hpke_metadata
        .seal(
            &recipient_md_pubkey,
            HPKE_BASE_INFO, // b""
            HPKE_AAD,       // b""
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
        ct_message: message_ciphertext,
        message_dhakem_ss_encap: dhakem_ss_encaps_bytes,
        message_pqpsk_ss_encap: psk_ct,
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
                    HPKE_AAD,
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

    let psk = MlKem768::decaps(
        &combined_ct.message_pqpsk_ss_encap,
        receiver_keys.get_pq_kem_psk_sk(),
    )
    .unwrap();

    let pt = hpke_authenc
        .open(
            &combined_ct.message_dhakem_ss_encap,
            hpke_receiver_keys.private_key(),
            &combined_ct.message_pqpsk_ss_encap,
            HPKE_AAD,
            &combined_ct.ct_message,
            Some(&psk),
            Some(HPKE_PSK_ID),
            Some(&hpke_pubkey_sender),
        )
        .expect("Decryption failed");

    // TODO parse
    Plaintext {
        msg: pt,
        recipient_pubkey_dhakem: None,
        sender_reply_pubkey_dhakem: None,
        sender_reply_pubkey_pq_psk: None,
        sender_reply_pubkey_hybrid: None,
        sender_fetch_key: None,
    }
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

pub struct Source {
    keys: KeyBundle,
    sk_fetch: [u8; LEN_DH_ITEM],
    pk_fetch: [u8; LEN_DH_ITEM],
}

impl Source {
    /// This doesn't use keys bootstrapped from a passphrase;
    /// for now it's the same as journalist setup
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (sk_dh, pk_dh) = generate_dh_akem_keypair(rng).expect("DH keygen (DH-AKEM) failed");

        let mut pk_fetch: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        let mut sk_fetch: [u8; LEN_DHKEM_DECAPS_KEY] =
            generate_random_scalar(rng).expect("DH keygen (Fetching) failed!");
        let _ = libcrux_curve25519::secret_to_public(&mut pk_fetch, &mut sk_fetch);

        let (sk_pqkem_psk, pk_pqkem_psk) =
            generate_mlkem768_keypair(rng).expect("Failed to generate ml-kem keys!");

        let (sk_md, pk_md) = generate_xwing_keypair(rng).expect("Failed to generate xwing keys");

        let keybundle = KeyBundle {
            dhakem_sk: *sk_dh.as_bytes(),
            dhakem_pk: *pk_dh.as_bytes(),
            pq_kem_psk_sk: *sk_pqkem_psk.as_bytes(),
            pq_kem_psk_pk: *pk_pqkem_psk.as_bytes(),
            hybrid_md_sk: *sk_md.as_bytes(),
            hybrid_md_pk: *pk_md.as_bytes(),
        };

        Self {
            keys: keybundle,
            sk_fetch: sk_fetch,
            pk_fetch: pk_fetch,
        }
    }
}

impl User for Source {
    fn keybundle(&self, _: Option<usize>) -> &KeyBundle {
        &self.keys
    }
    fn get_fetch_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.sk_fetch
    }
    fn get_fetch_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.pk_fetch
    }

    // this is silly, and is just for benchmarking simplicity to have one
    // send/receive method that works for all sender and recipient types
    fn get_all_keys(&self) -> &[KeyBundle] {
        use core::slice;
        slice::from_ref(&self.keys)
    }
}

pub struct Journalist {
    keybundle: Vec<KeyBundle>,

    sk_fetch: [u8; LEN_DH_ITEM],
    pk_fetch: [u8; LEN_DH_ITEM],

    sk_reply: [u8; LEN_DH_ITEM],
    pk_reply: [u8; LEN_DH_ITEM],
}

impl Journalist {
    /// Set up Journalist, creating key_bundle_size short-term key bundles.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, num_keybundles: usize) -> Self {
        let mut key_bundle: Vec<KeyBundle> = Vec::with_capacity(num_keybundles);

        let mut pk_fetch: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        let mut sk_fetch: [u8; LEN_DHKEM_DECAPS_KEY] =
            generate_random_scalar(rng).expect("DH keygen (Fetching) failed!");
        let _ = libcrux_curve25519::secret_to_public(&mut pk_fetch, &mut sk_fetch);

        // We don't currently benchmark replies, but this key
        // would be used by journalist for replying to sources
        let mut pk_reply: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        let mut sk_reply: [u8; LEN_DHKEM_DECAPS_KEY] =
            generate_random_scalar(rng).expect("DH keygen (Reply) failed!");
        let _ = libcrux_curve25519::secret_to_public(&mut pk_reply, &mut sk_reply);

        // Generate one-time/short-lived keybundles
        for _ in 0..num_keybundles {
            let (sk_dh, pk_dh) = generate_dh_akem_keypair(rng).expect("DH keygen (DH-AKEM) failed");

            let (sk_pqkem_psk, pk_pqkem_psk) =
                generate_mlkem768_keypair(rng).expect("Failed to generate ml-kem keys!");

            let (sk_md, pk_md) =
                generate_xwing_keypair(rng).expect("Failed to generate xwing keys");

            let bundle = KeyBundle {
                dhakem_sk: *sk_dh.as_bytes(),
                dhakem_pk: *pk_dh.as_bytes(),
                pq_kem_psk_sk: *sk_pqkem_psk.as_bytes(),
                pq_kem_psk_pk: *pk_pqkem_psk.as_bytes(),
                hybrid_md_sk: *sk_md.as_bytes(),
                hybrid_md_pk: *pk_md.as_bytes(),
            };

            key_bundle.push(bundle);
        }
        // (sanity)
        assert_eq!(key_bundle.len(), num_keybundles);

        Self {
            keybundle: key_bundle,
            sk_fetch: sk_fetch,
            pk_fetch: pk_fetch,
            sk_reply: sk_reply,
            pk_reply: pk_reply,
        }
    }
}

impl User for Journalist {
    // Get a specific index, or a random bundle.
    // In reality, the server will publish pubkey bundles
    fn keybundle(&self, index: Option<usize>) -> &KeyBundle {
        match index {
            Some(i) => self
                .keybundle
                .get(i)
                .unwrap_or_else(|| panic!("Bad index: {}", i)),
            None => {
                let mut rng = setup_rng();
                let choice = rng.next_u32() as usize % &self.keybundle.len();

                self.keybundle
                    .get(choice)
                    .expect("Need at least one keybundle")
            }
        }
    }

    fn get_all_keys(&self) -> &[KeyBundle] {
        &self.keybundle
    }

    fn get_fetch_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.sk_fetch
    }
    fn get_fetch_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.pk_fetch
    }
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
        let plaintext = b"Encrypt-decrypt test".to_vec();

        // TODO
        let pt = Plaintext {
            sender_reply_pubkey_pq_psk: Some(sender.keys.get_pq_kem_psk_pk().to_vec()),
            sender_reply_pubkey_dhakem: Some(sender.keys.get_dhakem_pk().to_vec()),
            sender_fetch_key: Some(sender.pk_fetch.to_vec()),
            sender_reply_pubkey_hybrid: None,
            recipient_pubkey_dhakem: None,
            msg: b"Encrypt-decrypt test".to_vec(),
        };

        let envelope = encrypt(&mut rng, &sender, &plaintext, &recipient, None);
        let decrypted = decrypt(&recipient, &envelope);

        assert_eq!(decrypted.msg, plaintext);
        // TODO: Add more fields to plaintext, and add assertions
    }

    #[test]
    fn test_fetch_challenges_roundtrip() {
        let mut rng = setup_rng();

        let journalist = Journalist::new(&mut rng, 2);
        let source = Source::new(&mut rng);

        let plaintext = b"Fetch this message".to_vec();
        let envelope = encrypt(&mut rng, &source, &plaintext, &journalist, None);

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

// Begin benchmark functions
pub fn bench_encrypt(
    seed32: [u8; 32],
    sender: &dyn User,
    recipient: &dyn User,
    recipient_bundle_index: usize,
    plaintext: &[u8],
) -> Envelope {
    let mut rng = ChaCha20Rng::from_seed(seed32);
    encrypt(
        &mut rng,
        sender,
        plaintext,
        recipient,
        Some(recipient_bundle_index),
    )
}

pub fn bench_decrypt(recipient: &dyn User, envelope: &Envelope) -> Plaintext {
    decrypt(recipient, envelope)
}

pub fn bench_fetch(recipient: &dyn User, challenges: Vec<FetchResponse>) -> Vec<Vec<u8>> {
    solve_fetch_challenges(recipient, challenges)
}
