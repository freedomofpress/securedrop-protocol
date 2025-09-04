use hpke_rs::libcrux::HpkeLibcrux;
use hpke_rs::{HpkeKeyPair, HpkePrivateKey, HpkePublicKey};
use libcrux_curve25519::hacl::scalarmult;
use libcrux_kem::MlKem768;
use libcrux_traits::kem::secrets::Kem;
use rand::RngCore;
use rand::rngs::StdRng;
use rand_core::CryptoRng;
use rand_core::SeedableRng;
use securedrop_protocol::primitives::dh_akem::generate_dh_akem_keypair;
use securedrop_protocol::primitives::mlkem::generate_mlkem768_keypair;
use securedrop_protocol::primitives::x25519::generate_dh_keypair;
use securedrop_protocol::primitives::x25519::generate_random_scalar;
use securedrop_protocol::primitives::xwing::generate_xwing_keypair;
use securedrop_protocol::primitives::{decrypt_message_id, encrypt_message_id};
use std::vec::Vec;

const HPKE_PSK_ID: &[u8] = b"PSK_INFO_ID_TAG"; // Spec requires a tag
const HPKE_INFO: &[u8] = b"";
const HPKE_AAD: &[u8] = b"";

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

// "Metadata" aka sender pubkey and encapsulated secrets
const METADATA_LENGTH: usize =
    LEN_DH_ITEM + LEN_MLKEM_SHAREDSECRET_ENCAPS + LEN_DHKEM_SHAREDSECRET_ENCAPS;

// Message ID (uuid) and KMID
const LEN_MESSAGE_ID: usize = 16;
// TODO: this will be aes-gcm and use AES GCM TagSize
const LEN_KMID: usize = libcrux_chacha20poly1305::TAG_LEN + LEN_MESSAGE_ID;

#[derive(Debug)]
pub struct Envelope {
    cmessage: Vec<u8>,
    cmetadata: Vec<u8>,
    metadata_encap: [u8; LEN_XWING_SHAREDSECRET_ENCAPS],
    mgdh_pubkey: [u8; LEN_DH_ITEM],
    mgdh: [u8; LEN_DH_ITEM],
}

#[derive(Debug)]
pub struct Plaintext {
    msg: Vec<u8>,
    sender_key: Vec<u8>,
    recipient_reply_key_classical_msg: Option<Vec<u8>>, // DH-AKEM
    recipient_reply_key_pq_psk_msg: Option<Vec<u8>>,    // ML-KEM768
    recipient_reply_key_hybrid_md: Option<Vec<u8>>,     // XWING
}

/// Represent stored ciphertexts on the server
pub struct ServerMessageStore {
    message_id: [u8; LEN_MESSAGE_ID],
    mgdh: [u8; LEN_DH_ITEM],
    mgdh_pubkey: [u8; LEN_DH_ITEM],
    ciphertext: Vec<u8>,
}

pub struct FetchResponse {
    enc_id: [u8; LEN_KMID],   // aka kmid
    pmgdh: [u8; LEN_DH_ITEM], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; LEN_DH_ITEM]) -> Self {
        Self { enc_id, pmgdh }
    }
}

// Plaintext metadata
pub struct Metadata {
    pub sender_pubkey_bytes: [u8; LEN_DH_ITEM],
    pub pq_psk_ss_encaps: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS],
    pub dhakem_ss_encaps: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS],
}

// TODO: NOT FOR PROD, parsing untrusted ct
impl Metadata {
    /// Serialize Metadata.
    /// [0:LEN_DHKEM_ENCAPS_KEY] is sender pubkey
    /// [LEN_DHKEM_ENCAPS_KEY:LEN_DHKEM_ENCAPS_KEY+LEN_MLKEM_SS_ENCAPS] is PSK encaps
    /// [LEN_DHKEM_ENCAPS_KEY+LEN_MLKEM_SS_ENCAPS:] is dh-akem enc encaps
    /// Order may change in final version
    pub fn to_bytes(&self) -> [u8; METADATA_LENGTH] {
        let mut bytes = [0u8; METADATA_LENGTH];
        bytes[0..LEN_DHKEM_ENCAPS_KEY].copy_from_slice(&self.sender_pubkey_bytes);
        bytes[LEN_DHKEM_ENCAPS_KEY..LEN_DHKEM_ENCAPS_KEY + LEN_MLKEM_SHAREDSECRET_ENCAPS]
            .copy_from_slice(&self.pq_psk_ss_encaps);
        bytes[LEN_DHKEM_ENCAPS_KEY + LEN_MLKEM_SHAREDSECRET_ENCAPS..]
            .copy_from_slice(&self.dhakem_ss_encaps);
        bytes
    }
}

impl std::convert::TryFrom<&[u8]> for Metadata {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != METADATA_LENGTH {
            return Err("Metadata length error");
        }

        let sender_pubkey_bytes = bytes[0..LEN_DHKEM_ENCAPS_KEY]
            .try_into()
            .expect("Metadata slice -> array error [0:32]");
        let pq_psk_end = LEN_DHKEM_ENCAPS_KEY + LEN_MLKEM_SHAREDSECRET_ENCAPS;
        let pq_psk_ss_encaps = bytes[LEN_DHKEM_ENCAPS_KEY..pq_psk_end]
            .try_into()
            .expect("Metadata slice -> array error [32:32+1088]");
        let dhakem_ss_encaps = bytes[pq_psk_end..]
            .try_into()
            .expect("Metadata slice -> array error [32+1088:]");

        Ok(Metadata {
            sender_pubkey_bytes,
            pq_psk_ss_encaps,
            dhakem_ss_encaps,
        })
    }
}

impl From<[u8; METADATA_LENGTH]> for Metadata {
    fn from(bytes: [u8; METADATA_LENGTH]) -> Self {
        Metadata::try_from(&bytes[..]).expect("Need valid array length")
    }
}

pub trait User {
    // msg enc classical
    fn get_dhakem_sk(&self) -> &[u8; LEN_DH_ITEM];
    fn get_dhakem_pk(&self) -> &[u8; LEN_DH_ITEM];

    // msg enc pq psk
    fn get_pq_kem_psk_pk(&self) -> &[u8; LEN_MLKEM_ENCAPS_KEY];
    fn get_pq_kem_psk_sk(&self) -> &[u8; LEN_MLKEM_DECAPS_KEY];

    // md enc hybrid
    fn get_hybrid_md_pk(&self) -> &[u8; LEN_XWING_ENCAPS_KEY];
    fn get_hybrid_md_sk(&self) -> &[u8; LEN_XWING_DECAPS_KEY];

    // fetch classical
    fn get_fetch_sk(&self) -> &[u8; LEN_DH_ITEM];
    fn get_fetch_pk(&self) -> &[u8; LEN_DH_ITEM];
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

    let recipient_dhakem_pubkey = hpke_pubkey_from_bytes(recipient.get_dhakem_pk());

    let sender_hpke_keypair =
        hpke_keypair_from_bytes(sender.get_dhakem_sk(), sender.get_dhakem_pk());

    // Note: Don't need SEED_GEN len randomness (64), just SHARED_SECRET len (32),
    // according to MLK-KEM source code.
    let mut randomness: [u8; LEN_MLKEM_SHAREDSECRET] = [0u8; LEN_MLKEM_SHAREDSECRET];
    rand::rng().fill_bytes(&mut randomness);

    // Calculate PQ PSK - encapsulate to the recipient's key
    let (psk, psk_ct) =
        MlKem768::encaps(recipient.get_pq_kem_psk_pk(), &randomness).expect("PSK encaps failed");

    // HPKE AuthPSK message encryption
    let (mesage_dhakem_shared_secret_encaps, message_ciphertext) = hpke_authenc
        .seal(
            &recipient_dhakem_pubkey,
            HPKE_INFO,
            HPKE_AAD,
            plaintext,
            Some(&psk),
            Some(HPKE_PSK_ID),                       // Fixed PSK ID
            Some(sender_hpke_keypair.private_key()), // sender DH-AKEM private key
        )
        .unwrap();

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

    let dhakem_ss_encaps: [u8; LEN_DH_ITEM] = mesage_dhakem_shared_secret_encaps
        .try_into()
        .expect(&format!("Need {} bytes", LEN_DH_ITEM));

    // Build Plaintext metadata
    let metadata_bytes = Metadata {
        sender_pubkey_bytes: sender_pubkey_bytes,
        pq_psk_ss_encaps: psk_ct,
        dhakem_ss_encaps: dhakem_ss_encaps,
    }
    .to_bytes();

    // Serialize then encrypt metadata with metadata key (xwing) and Hpke Base mode
    let recipient_md_pubkey = hpke_pubkey_from_bytes(recipient.get_hybrid_md_pk());

    let (md_ss_encaps_vec, metadata_ciphertext) = hpke_metadata
        .seal(
            &recipient_md_pubkey,
            HPKE_INFO,
            HPKE_AAD,
            &metadata_bytes,
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

    Envelope {
        cmessage: message_ciphertext,
        cmetadata: metadata_ciphertext,
        metadata_encap: metadata_ss_encaps,
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

    let receiver_metadata_keypair =
        hpke_keypair_from_bytes(receiver.get_hybrid_md_sk(), receiver.get_hybrid_md_pk());

    let receiver_dhakem_keypair =
        hpke_keypair_from_bytes(receiver.get_dhakem_sk(), receiver.get_dhakem_pk());

    let raw_metadata = hpke_base
        .open(
            &envelope.metadata_encap,
            receiver_metadata_keypair.private_key(),
            HPKE_INFO,
            HPKE_AAD,
            &envelope.cmetadata,
            None,
            None,
            None,
        )
        .expect("Wanted decrypted metadata");

    let raw_md_bytes: [u8; METADATA_LENGTH] =
        raw_metadata.try_into().expect("Need METADATA_LENGTH array");
    let metadata = Metadata::try_from(raw_md_bytes).unwrap();

    let hpke_pubkey_sender = hpke_pubkey_from_bytes(&metadata.sender_pubkey_bytes);

    let psk = MlKem768::decaps(&metadata.pq_psk_ss_encaps, receiver.get_pq_kem_psk_sk()).unwrap();

    let pt = hpke_authenc
        .open(
            &metadata.dhakem_ss_encaps,
            receiver_dhakem_keypair.private_key(),
            HPKE_INFO,
            HPKE_AAD,
            &envelope.cmessage,
            Some(&psk),
            Some(HPKE_PSK_ID),
            Some(&hpke_pubkey_sender),
        )
        .expect("Decryption failed");

    // TODO
    Plaintext {
        msg: pt,
        sender_key: hpke_pubkey_sender.as_slice().to_vec(),
        recipient_reply_key_classical_msg: None,
        recipient_reply_key_pq_psk_msg: None,
        recipient_reply_key_hybrid_md: None,
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
        let _ = scalarmult(&mut shared_secret, &eph_sk_bytes, &entry.mgdh_pubkey);
        let kmid: [u8; LEN_KMID] = encrypt_message_id(&shared_secret, message_id)
            .unwrap()
            .try_into()
            .expect(&format!("Need {} bytes", LEN_KMID));

        // 2-party DH yields per-request clue (pmgdh) used by intended recipient
        // to compute shared_secret
        let mut pmgdh: [u8; LEN_DHKEM_SHARED_SECRET] = [0u8; LEN_DHKEM_SHARED_SECRET];
        let _ = scalarmult(&mut pmgdh, &eph_sk_bytes, &entry.mgdh_pubkey);

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
    sk_dh: [u8; LEN_DHKEM_DECAPS_KEY],
    pk_dh: [u8; LEN_DHKEM_ENCAPS_KEY],
    sk_pqkem_psk: [u8; LEN_MLKEM_DECAPS_KEY],
    pk_pqkem_psk: [u8; LEN_MLKEM_ENCAPS_KEY],
    sk_md: [u8; LEN_XWING_DECAPS_KEY],
    pk_md: [u8; LEN_XWING_ENCAPS_KEY],
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
        let _ = libcrux_curve25519::secret_to_public(&mut sk_fetch, &mut pk_fetch);

        let (sk_pqkem_psk, pk_pqkem_psk) =
            generate_mlkem768_keypair(rng).expect("Failed to generate ml-kem keys!");

        let (sk_md, pk_md) = generate_xwing_keypair(rng).expect("Failed to generate xwing keys");
        Self {
            sk_dh: *sk_dh.as_bytes(),
            pk_dh: *pk_dh.as_bytes(),
            sk_pqkem_psk: *sk_pqkem_psk.as_bytes(),
            pk_pqkem_psk: *pk_pqkem_psk.as_bytes(),
            sk_md: *sk_md.as_bytes(), // TODO
            pk_md: *pk_md.as_bytes(),
            sk_fetch: sk_fetch,
            pk_fetch: pk_fetch,
        }
    }
}

impl User for Source {
    fn get_dhakem_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.sk_dh
    }
    fn get_dhakem_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.pk_dh
    }
    fn get_fetch_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.sk_fetch
    }
    fn get_fetch_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.pk_fetch
    }
    fn get_hybrid_md_pk(&self) -> &[u8; LEN_XWING_ENCAPS_KEY] {
        &self.pk_md
    }
    fn get_hybrid_md_sk(&self) -> &[u8; LEN_XWING_DECAPS_KEY] {
        &self.sk_md
    }
    fn get_pq_kem_psk_pk(&self) -> &[u8; LEN_MLKEM_ENCAPS_KEY] {
        &self.pk_pqkem_psk
    }
    fn get_pq_kem_psk_sk(&self) -> &[u8; LEN_MLKEM_DECAPS_KEY] {
        &self.sk_pqkem_psk
    }
}

pub struct Journalist {
    sk_dh: [u8; LEN_DHKEM_DECAPS_KEY],
    pk_dh: [u8; LEN_DHKEM_ENCAPS_KEY],
    sk_pqkem_psk: [u8; LEN_MLKEM_DECAPS_KEY],
    pk_pqkem_psk: [u8; LEN_MLKEM_ENCAPS_KEY],
    sk_md: [u8; LEN_XWING_DECAPS_KEY],
    pk_md: [u8; LEN_XWING_ENCAPS_KEY],
    sk_fetch: [u8; LEN_DH_ITEM],
    pk_fetch: [u8; LEN_DH_ITEM],
}

impl Journalist {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (sk_dh, pk_dh) = generate_dh_akem_keypair(rng).expect("DH keygen (DH-AKEM) failed");

        let mut pk_fetch: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        let mut sk_fetch: [u8; LEN_DHKEM_DECAPS_KEY] =
            generate_random_scalar(rng).expect("DH keygen (Fetching) failed!");
        let _ = libcrux_curve25519::secret_to_public(&mut sk_fetch, &mut pk_fetch);

        let (sk_pqkem_psk, pk_pqkem_psk) =
            generate_mlkem768_keypair(rng).expect("Failed to generate ml-kem keys!");

        let (sk_md, pk_md) = generate_xwing_keypair(rng).expect("Failed to generate xwing keys");
        Self {
            sk_dh: *sk_dh.as_bytes(),
            pk_dh: *pk_dh.as_bytes(),
            sk_pqkem_psk: *sk_pqkem_psk.as_bytes(),
            pk_pqkem_psk: *pk_pqkem_psk.as_bytes(),
            sk_md: *sk_md.as_bytes(), // TODO
            pk_md: *pk_md.as_bytes(),
            sk_fetch: sk_fetch,
            pk_fetch: pk_fetch,
        }
    }
}

impl User for Journalist {
    fn get_dhakem_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.sk_dh
    }
    fn get_dhakem_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.pk_dh
    }
    fn get_fetch_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.sk_fetch
    }
    fn get_fetch_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.pk_fetch
    }
    fn get_hybrid_md_pk(&self) -> &[u8; LEN_XWING_ENCAPS_KEY] {
        &self.pk_md
    }
    fn get_hybrid_md_sk(&self) -> &[u8; LEN_XWING_DECAPS_KEY] {
        &self.sk_md
    }
    fn get_pq_kem_psk_pk(&self) -> &[u8; LEN_MLKEM_ENCAPS_KEY] {
        &self.pk_pqkem_psk
    }
    fn get_pq_kem_psk_sk(&self) -> &[u8; LEN_MLKEM_DECAPS_KEY] {
        &self.sk_pqkem_psk
    }
}
