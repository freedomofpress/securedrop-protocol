use crate::primitives::dh_akem::generate_dh_akem_keypair;
use crate::primitives::mlkem::generate_mlkem768_keypair;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::x25519::generate_random_scalar;
use crate::primitives::xwing::generate_xwing_keypair;
use alloc::{format, vec::Vec};
use anyhow::Error;
use getrandom;
use hpke_rs::{HpkeKeyPair, HpkePublicKey};
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

#[derive(Debug, Clone)]
pub struct CombinedCiphertext {
    // dh-akem ss encaps (needed to decrypt message)
    pub(crate) message_dhakem_ss_encap: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS],

    // pq psk encap (needed to decaps psk)
    // also passed as part of `info` param during hpke.authopen
    pub(crate) message_pqpsk_ss_encap: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS],

    // authenc message ciphertext
    pub(crate) ct_message: Vec<u8>,
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
            message_dhakem_ss_encap: dhakem_ss_encaps,
            message_pqpsk_ss_encap: pqpsk_ss_encaps,
            ct_message: (cmessage),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Envelope {
    // (message_ciphertext || message_dhakem_ss_encap || msg_psk_ss_encap)
    // see CombinedCiphertext
    pub(crate) cmessage: Vec<u8>,

    // baseenc "metadata", aka sender pubkey
    pub(crate) cmetadata: Vec<u8>,

    // "metadata" encaps shared secret
    pub(crate) metadata_encap: [u8; LEN_XWING_SHAREDSECRET_ENCAPS],

    // clue material
    pub(crate) mgdh_pubkey: [u8; LEN_DH_ITEM],
    pub(crate) mgdh: [u8; LEN_DH_ITEM],
}

#[derive(Debug)]
/// Toy pt structure - provide params in order
pub struct Plaintext {
    pub sender_reply_pubkey_pq_psk: [u8; LEN_MLKEM_ENCAPS_KEY],
    pub sender_reply_pubkey_hybrid: [u8; LEN_XWING_ENCAPS_KEY],
    pub sender_fetch_key: [u8; LEN_DH_ITEM],
    pub msg: Vec<u8>,
}

impl Plaintext {
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.sender_reply_pubkey_pq_psk);
        buf.extend_from_slice(&self.sender_reply_pubkey_hybrid);
        buf.extend_from_slice(&self.sender_fetch_key);
        buf.extend_from_slice(&self.msg);

        buf
    }

    pub fn len(&self) -> usize {
        return LEN_MLKEM_ENCAPS_KEY + LEN_XWING_ENCAPS_KEY + LEN_DH_ITEM + &self.msg.len();
    }

    // Toy parsing only
    pub fn from_bytes(pt_bytes: &Vec<u8>) -> Result<Self, Error> {
        let mut offset = 0;

        let mut sender_reply_pubkey_pq_psk = [0u8; LEN_MLKEM_ENCAPS_KEY];
        sender_reply_pubkey_pq_psk
            .copy_from_slice(&pt_bytes[offset..offset + LEN_MLKEM_ENCAPS_KEY]);
        offset += LEN_MLKEM_ENCAPS_KEY;

        let mut sender_reply_pubkey_hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
        sender_reply_pubkey_hybrid
            .copy_from_slice(&pt_bytes[offset..offset + LEN_XWING_ENCAPS_KEY]);
        offset += LEN_XWING_ENCAPS_KEY;

        let mut sender_fetch_key = [0u8; LEN_DH_ITEM];
        sender_fetch_key.copy_from_slice(&pt_bytes[offset..offset + LEN_DH_ITEM]);
        offset += LEN_DH_ITEM;

        let msg = pt_bytes[offset..].to_vec();

        Ok(Plaintext {
            sender_reply_pubkey_pq_psk,
            sender_reply_pubkey_hybrid,
            sender_fetch_key,
            msg,
        })
    }
}

/// Represent stored ciphertexts on the server
pub struct ServerMessageStore {
    pub(crate) message_id: [u8; LEN_MESSAGE_ID],
    pub(crate) envelope: Envelope,
}

pub struct FetchResponse {
    pub(crate) enc_id: [u8; LEN_KMID],   // aka kmid
    pub(crate) pmgdh: [u8; LEN_DH_ITEM], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; LEN_DH_ITEM]) -> Self {
        Self {
            enc_id: enc_id,
            pmgdh: pmgdh,
        }
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
    pub(crate) fn get_dhakem_sk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.dhakem_sk
    }
    pub(crate) fn get_dhakem_pk(&self) -> &[u8; LEN_DH_ITEM] {
        &self.dhakem_pk
    }

    // msg enc pq psk
    pub(crate) fn get_pq_kem_psk_pk(&self) -> &[u8; LEN_MLKEM_ENCAPS_KEY] {
        &self.pq_kem_psk_pk
    }

    pub(crate) fn get_pq_kem_psk_sk(&self) -> &[u8; LEN_MLKEM_DECAPS_KEY] {
        &self.pq_kem_psk_sk
    }

    // md enc hybrid
    pub(crate) fn get_hybrid_md_pk(&self) -> &[u8; LEN_XWING_ENCAPS_KEY] {
        &self.hybrid_md_pk
    }

    pub(crate) fn get_hybrid_md_sk(&self) -> &[u8; LEN_XWING_DECAPS_KEY] {
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

pub struct Source {
    pub keys: KeyBundle,
    sk_fetch: [u8; LEN_DH_ITEM],
    pub pk_fetch: [u8; LEN_DH_ITEM],
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
    pub(crate) keybundle: Vec<KeyBundle>,

    pub(crate) sk_fetch: [u8; LEN_DH_ITEM],
    pub(crate) pk_fetch: [u8; LEN_DH_ITEM],

    pub(crate) sk_reply: [u8; LEN_DH_ITEM],
    pub(crate) pk_reply: [u8; LEN_DH_ITEM],
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
