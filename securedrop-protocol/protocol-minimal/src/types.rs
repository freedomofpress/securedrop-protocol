use crate::SelfSignature;
use crate::Signature;
use crate::SigningKey;
use crate::VerifyingKey;
use crate::api::Api;
use crate::api::JournalistApi;
use crate::api::restricted;
use crate::primitives::dh_akem::DhAkemPrivateKey;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::dh_akem::deterministic_keygen as kgen_deterministic_dhakem;
use crate::primitives::dh_akem::generate_dh_akem_keypair;
use crate::primitives::mlkem::MLKEM768PrivateKey;
use crate::primitives::mlkem::MLKEM768PublicKey;
use crate::primitives::mlkem::deterministic_keygen as kgen_deterministic_mlkem;
use crate::primitives::mlkem::generate_mlkem768_keypair;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::deterministic_dh_keygen;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::xwing::XWingPrivateKey;
use crate::primitives::xwing::XWingPublicKey;
use crate::primitives::xwing::deterministic_keygen as kgen_deterministic_xwing;
use crate::primitives::xwing::generate_xwing_keypair;
use alloc::vec::Vec;
use anyhow::Error;
use libcrux_sha2::Digest;
use rand_core::{CryptoRng, RngCore};

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

#[derive(Debug, Clone)]
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

#[derive(Clone)]
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

/// Generic KeyPair
pub struct KeyPair<SK, PK> {
    pub(crate) sk: SK,
    pub(crate) pk: PK,
}

/// The keypairs we actually use
pub type MlKem768KeyPair = KeyPair<MLKEM768PrivateKey, MLKEM768PublicKey>;
pub type DhAkemKeyPair = KeyPair<DhAkemPrivateKey, DhAkemPublicKey>;
// silly name but include "fetch" for disambiguation with dh-akem.
// eventually: ristretto255
pub type DhFetchKeyPair = KeyPair<DHPrivateKey, DHPublicKey>;
pub type SigningKeyPair = KeyPair<SigningKey, VerifyingKey>;
pub type XWingKeyPair = KeyPair<XWingPrivateKey, XWingPublicKey>;

pub type SignedKeyBundlePublic = (KeyBundlePublic, SelfSignature);

#[derive(Debug, Clone)]
pub struct KeyBundlePublic {
    pub dhakem_pk: DhAkemPublicKey,
    pub mlkem_pk: MLKEM768PublicKey,
    pub xwing_pk: XWingPublicKey,
}

impl KeyBundlePublic {
    // Serialize in a specific order, i.e. for signing
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.dhakem_pk.as_bytes());
        out.extend(self.mlkem_pk.as_bytes());
        out.extend(self.xwing_pk.as_bytes());
        out
    }
}

// pub struct BorrowedKeyBundlePublic<'a> {
//     pub dhakem_pk: &'a DhAkemPublicKey,
//     pub mlkem_pk: &'a MLKEM768PublicKey,
//     pub xwing_pk: &'a XWingPublicKey,
// }

// impl<'a> BorrowedKeyBundlePublic<'a> {
//     // Serialize in a specific order, i.e. for signing

//     pub(crate) fn to_owned(&self) -> KeyBundlePublic {
//         KeyBundlePublic {
//             dhakem_pk: self.dhakem_pk.clone(),
//             mlkem_pk: self.mlkem_pk.clone(),
//             xwing_pk: self.xwing_pk.clone(),
//         }
//     }
// }

pub(crate) struct MessageKeyBundle {
    pub(crate) dh_akem: DhAkemKeyPair,
    pub(crate) mlkem: MlKem768KeyPair,
    pub(crate) xwing_md: XWingKeyPair,
}

impl MessageKeyBundle {
    pub fn new(dh_akem: DhAkemKeyPair, mlkem: MlKem768KeyPair, xwing_md: XWingKeyPair) -> Self {
        // // ID is derived from pubkey hashes in specific order
        // let mut hasher = libcrux_sha2::Sha256::default();

        // hasher.update(dh_akem.pk.as_bytes());
        // hasher.update(mlkem.pk.as_bytes());
        // hasher.update(xwing_md.pk.as_bytes());

        // let mut id = [0u8; 32];
        // let _ = hasher.finish(&mut id);

        Self {
            dh_akem,
            mlkem,
            xwing_md,
        }
    }
    pub(crate) fn public(&self) -> KeyBundlePublic {
        KeyBundlePublic {
            dhakem_pk: self.dh_akem.pk.clone(),
            mlkem_pk: self.mlkem.pk.clone(),
            xwing_pk: self.xwing_md.pk.clone(),
        }
    }
}

pub(crate) struct SignedMessageKeyBundle {
    bundle: MessageKeyBundle,
    selfsig: SelfSignature,
}

#[derive(Debug, Clone)]
pub struct SignedLongtermPubKeyBytes(pub [u8; LEN_DH_ITEM + LEN_DHKEM_ENCAPS_KEY]);

impl SignedLongtermPubKeyBytes {
    fn from_keys(fetch_pk: &DHPublicKey, reply_dhakem: &DhAkemPublicKey) -> Self {
        let mut pubkey_bytes = [0u8; LEN_DH_ITEM + LEN_DHKEM_ENCAPS_KEY];
        pubkey_bytes[0..LEN_DH_ITEM].copy_from_slice(&fetch_pk.into_bytes());
        pubkey_bytes[LEN_DH_ITEM..].copy_from_slice(reply_dhakem.as_bytes());

        Self { 0: pubkey_bytes }
    }
}

#[derive(Clone)]
pub struct Enrollment {
    pub bundle: SignedLongtermPubKeyBytes,
    pub selfsig: SelfSignature,
    pub keys: (VerifyingKey, DHPublicKey, DhAkemPublicKey),
}

// in memory session storage
pub struct SessionStorage {
    pub fpf_key: Option<VerifyingKey>,
    pub nr_key: Option<VerifyingKey>,
    pub fpf_signature: Option<Signature>,
}

////////////////////////
///
/// Users have the following (public traits) in common:
/// They expose a fetch pubkey, a message auth pubkey
/// (implicit authentication),
/// and a collection of KeyBundles (tuples of keys - a keybundle contains
/// all the key material required to send a message to a given user).
/// A Source has a KeyBundle collection of size 1.
/// A Journalist has KeyBundle collection of size > 1.
/// Some users (Sources) use a key from their message bundle as
/// their message auth key.
pub trait UserPublic {
    fn fetch_pk(&self) -> &DHPublicKey;
    fn message_auth_pk(&self) -> &DhAkemPublicKey;
    fn message_psk_pk(&self) -> &MLKEM768PublicKey;
    fn message_metadata_pk(&self) -> &XWingPublicKey;
    fn message_enc_pk(&self) -> &DhAkemPublicKey;
}

pub trait JournalistPublic: UserPublic {
    fn verifying_key(&self) -> &VerifyingKey;
    fn self_signature(&self) -> &SelfSignature;
    fn signed_keybytes(&self) -> &SignedLongtermPubKeyBytes;
}

pub trait Enrollable: private::Sealed {
    fn signing_key(&self) -> &VerifyingKey;
    fn enroll(&self) -> Enrollment;
    fn signed_keybundles(&self) -> impl Iterator<Item = SignedKeyBundlePublic>;
}

/// Sources: ingredients
/// Sources have a fetch key and an unsigned key bundle.
/// They reuse the dh-akem key within the keybundle where
/// journalists use a "reply key".
pub struct Source {
    fetch_key: DhFetchKeyPair,
    message_keys: MessageKeyBundle,
    passphrase: Vec<u8>,
    session: SessionStorage,
}

// Public-facing representation of a source,
// i.e., for receiving messages
pub struct SourcePublicView {
    fetch_pk: DHPublicKey,
    dhakem_pk: DhAkemPublicKey,
    message_pks: KeyBundlePublic,
}

/// Journalists: ingredients.
/// Journalists have a signing/verifying key, a reply key,
/// a fetch key, and a collection of one-time signed key bundles
pub struct Journalist {
    signing_key: SigningKeyPair,
    fetch_key: DhFetchKeyPair,
    message_keys: Vec<SignedMessageKeyBundle>,
    reply_key: DhAkemKeyPair,
    self_signature: SelfSignature,
    signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    session_storage: SessionStorage,
}

// Public-facing representation of a journalist
// used to send them a message
pub struct JournalistPublicView {
    vk: VerifyingKey,
    fetch_pk: DHPublicKey,
    dhakem_pk_reply: DhAkemPublicKey,
    signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    selfsig: SelfSignature,
    kb: SignedKeyBundlePublic,
}

// Seal Secret user traits behind a private module so that others can't access or implement them
// This could be more restricted than pub(crate), except we also use it for testing
pub(crate) mod private {
    pub trait Sealed {}
}

/// Users have the following (secret traits) in common:
/// They have a fetching keypair used to retrieve messages;
/// They have a message authentication keypair used to implicitly
/// authenticate their messages (via DH-AKEM);
/// They can index a KeyBundle (tuple) and use it to attempt to
/// decrypt a message.
pub trait UserSecret: private::Sealed {
    fn num_bundles(&self) -> usize;
    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey);
    fn message_auth_keypair(&self) -> (&DhAkemPrivateKey, &DhAkemPublicKey);
    fn build_message(&self, message: Vec<u8>) -> Plaintext;
    fn keybundles(&self) -> impl Iterator<Item = &MessageKeyBundle>;
}

/////////////////// users impl

impl JournalistPublicView {
    pub fn new(
        vk: VerifyingKey,
        fetch: DHPublicKey,
        dhakem: DhAkemPublicKey,
        selfsig: SelfSignature,
        signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
        kb: SignedKeyBundlePublic,
    ) -> Self {
        Self {
            vk,
            fetch_pk: fetch,
            dhakem_pk_reply: dhakem,
            selfsig,
            signed_longterm_key_bytes,
            kb,
        }
    }
}

impl UserPublic for SourcePublicView {
    fn fetch_pk(&self) -> &DHPublicKey {
        &self.fetch_pk
    }

    fn message_auth_pk(&self) -> &DhAkemPublicKey {
        &self.dhakem_pk
    }

    fn message_psk_pk(&self) -> &MLKEM768PublicKey {
        &self.message_pks.mlkem_pk
    }

    fn message_metadata_pk(&self) -> &XWingPublicKey {
        &self.message_pks.xwing_pk
    }

    fn message_enc_pk(&self) -> &DhAkemPublicKey {
        &self.message_pks.dhakem_pk
    }
}

impl UserPublic for JournalistPublicView {
    fn fetch_pk(&self) -> &DHPublicKey {
        &self.fetch_pk
    }

    fn message_auth_pk(&self) -> &DhAkemPublicKey {
        &self.dhakem_pk_reply
    }

    fn message_psk_pk(&self) -> &MLKEM768PublicKey {
        &self.kb.0.mlkem_pk
    }

    fn message_metadata_pk(&self) -> &XWingPublicKey {
        &self.kb.0.xwing_pk
    }

    fn message_enc_pk(&self) -> &DhAkemPublicKey {
        &self.kb.0.dhakem_pk
    }
}

impl JournalistPublic for JournalistPublicView {
    fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }

    fn self_signature(&self) -> &SelfSignature {
        &self.selfsig
    }

    fn signed_keybytes(&self) -> &SignedLongtermPubKeyBytes {
        &self.signed_longterm_key_bytes
    }
}

impl Api for Journalist {
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.session_storage.nr_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        self.session_storage.nr_key = Some(key);
    }
}

impl restricted::RestrictedApi for Journalist {}
impl JournalistApi for Journalist {}

impl Api for Source {
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.session.nr_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        self.session.nr_key = Some(key);
    }
}

impl private::Sealed for Source {}

/// Private, common to all users, implemented for sources
impl UserSecret for Source {
    fn num_bundles(&self) -> usize {
        1
    }

    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey) {
        (&self.fetch_key.sk, &self.fetch_key.pk)
    }

    fn message_auth_keypair(&self) -> (&DhAkemPrivateKey, &DhAkemPublicKey) {
        (&self.message_keys.dh_akem.sk, &self.message_keys.dh_akem.pk)
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        let mut reply_key_pq_psk = [0u8; LEN_MLKEM_ENCAPS_KEY];
        reply_key_pq_psk.copy_from_slice(self.message_keys.mlkem.pk.as_bytes());

        let mut fetch_pk = [0u8; LEN_DH_ITEM];
        fetch_pk.copy_from_slice(&self.fetch_key.pk.clone().into_bytes());

        let mut reply_key_pq_hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
        reply_key_pq_hybrid.copy_from_slice(self.message_keys.xwing_md.pk.as_bytes());

        Plaintext {
            sender_reply_pubkey_pq_psk: reply_key_pq_psk,
            sender_fetch_key: fetch_pk,
            sender_reply_pubkey_hybrid: reply_key_pq_hybrid,
            msg: message,
        }
    }

    fn keybundles(&self) -> impl Iterator<Item = &MessageKeyBundle> {
        core::iter::once(&self.message_keys)
    }
}

impl private::Sealed for Journalist {}
/// Private, common to all users, implemented for Journalists
impl UserSecret for Journalist {
    fn num_bundles(&self) -> usize {
        self.message_keys.len()
    }

    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey) {
        (&self.fetch_key.sk, &self.fetch_key.pk)
    }

    fn message_auth_keypair(&self) -> (&DhAkemPrivateKey, &DhAkemPublicKey) {
        // "reply key" (long term dh-akem key)
        (&self.reply_key.sk, &self.reply_key.pk)
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        // TODO: the journalist doesn't attach their own keys,
        // because the source pulls a fresh set of keys and verifies them
        // in order to reply. either fill with random bytes or use
        // another scheme (fixme)
        Plaintext {
            sender_reply_pubkey_pq_psk: [0u8; LEN_MLKEM_ENCAPS_KEY],
            sender_fetch_key: [0u8; LEN_DH_ITEM],
            sender_reply_pubkey_hybrid: [0u8; LEN_XWING_ENCAPS_KEY],
            msg: message,
        }
    }

    fn keybundles(&self) -> impl Iterator<Item = &MessageKeyBundle> {
        self.message_keys.iter().map(|signed| &signed.bundle)
    }
}

impl Enrollable for Journalist {
    fn enroll(&self) -> Enrollment {
        Enrollment {
            bundle: self.signed_longterm_key_bytes.clone(),
            selfsig: self.self_signature,
            keys: (
                self.signing_key.pk,
                self.fetch_key.pk.clone(),
                self.reply_key.pk.clone(),
            ),
        }
    }

    fn signed_keybundles(&self) -> impl Iterator<Item = SignedKeyBundlePublic> {
        self.message_keys
            .iter()
            .map(|k| (k.bundle.public(), k.selfsig))
    }

    fn signing_key(&self) -> &VerifyingKey {
        &self.signing_key.pk
    }
}

impl Source {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        // Generate a random passphrase
        let mut passphrase = [0u8; 32];
        rng.fill_bytes(&mut passphrase);

        // Derive all keys from the passphrase
        let source = Self::from_passphrase(&passphrase);
        source
    }

    pub fn passphrase(&self) -> &[u8] {
        &self.passphrase
    }

    /// Reconstruct keys from an existing passphrase
    ///
    /// TODO: What do we want to do here? This is not yet specified AFAICT
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        use blake2::{Blake2b, Digest};

        // DH-AKEM key
        let mut dh_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        dh_hasher.update(b"SD_DH_KEY");
        dh_hasher.update(passphrase);
        let dh_result = dh_hasher.finalize();

        // Fetch key
        let mut fetch_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        fetch_hasher.update(b"SD_FETCH_KEY");
        fetch_hasher.update(passphrase);
        let fetch_result = fetch_hasher.finalize();

        // Metadata Key
        let mut pke_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        pke_hasher.update(b"SD_PKE_KEY");
        pke_hasher.update(passphrase);
        let pke_result = pke_hasher.finalize();

        // PQ KEM PSK key
        let mut kem_hasher = Blake2b::<blake2::digest::typenum::U64>::new();
        kem_hasher.update(b"SD_KEM_KEY");
        kem_hasher.update(passphrase);
        let kem_result = kem_hasher.finalize();

        // Create key pairs
        let (dhakem_decaps, dhakem_encaps) =
            kgen_deterministic_dhakem(dh_result.into()).expect("Need DH-AKEM keygen");

        let (fetch_sk, fetch_pk): (DHPrivateKey, DHPublicKey) =
            deterministic_dh_keygen(fetch_result.into()).expect("Need Fetch keygen");

        // TODO: review derand kgen mechanism, see mlkem.rs
        let (mlkem_decaps, mlkem_encaps) =
            kgen_deterministic_mlkem(kem_result.into()).expect("Need MLKEM keygen");

        let (xwing_decaps, xwing_encaps) =
            kgen_deterministic_xwing(pke_result.into()).expect("Need X-Wing keygen");

        let session = SessionStorage {
            fpf_key: None,
            nr_key: None,
            fpf_signature: None,
        };

        Self {
            fetch_key: KeyPair {
                sk: fetch_sk,
                pk: fetch_pk,
            },
            message_keys: {
                MessageKeyBundle::new(
                    KeyPair {
                        sk: dhakem_decaps,
                        pk: dhakem_encaps,
                    },
                    KeyPair {
                        sk: mlkem_decaps,
                        pk: mlkem_encaps,
                    },
                    KeyPair {
                        sk: xwing_decaps,
                        pk: xwing_encaps,
                    },
                )
            },
            passphrase: passphrase.to_vec(),
            session: session,
        }
    }
    pub fn public(&self) -> SourcePublicView {
        SourcePublicView {
            fetch_pk: self.fetch_key.pk.clone(),
            dhakem_pk: self.message_keys.dh_akem.pk.clone(),
            message_pks: self.message_keys.public(),
        }
    }
}

impl Journalist {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, num_keybundles: usize) -> Self {
        let mut key_bundles: Vec<SignedMessageKeyBundle> = Vec::with_capacity(num_keybundles);

        let signing_key = SigningKey::new(&mut *rng).expect("Signing keygen failed");
        let verifying_key = signing_key.vk;

        let (sk_fetch, pk_fetch) =
            generate_dh_keypair(&mut *rng).expect("DH Keygen (Fetch) failed");

        let (sk_reply, pk_reply) =
            generate_dh_akem_keypair(&mut *rng).expect("DH-AKEM Keygen (Reply) failed");

        // Self-sign long-term pubkeys (for enrollment)
        let selfsigned_pubkeys = SignedLongtermPubKeyBytes::from_keys(&pk_fetch, &pk_reply);
        let s = SelfSignature(signing_key.sign(selfsigned_pubkeys.0.as_slice()));

        // Generate one-time/short-lived keybundles
        for _ in 0..num_keybundles {
            let (sk_dh, pk_dh) = generate_dh_akem_keypair(rng).expect("DH keygen (DH-AKEM) failed");

            let (sk_pqkem_psk, pk_pqkem_psk) =
                generate_mlkem768_keypair(rng).expect("Failed to generate ml-kem keys!");

            let (sk_md, pk_md) =
                generate_xwing_keypair(rng).expect("Failed to generate xwing keys");

            let bundle = MessageKeyBundle::new(
                KeyPair {
                    sk: sk_dh,
                    pk: pk_dh,
                },
                KeyPair {
                    sk: sk_pqkem_psk,
                    pk: pk_pqkem_psk,
                },
                KeyPair {
                    sk: sk_md,
                    pk: pk_md,
                },
            );

            let pubkey_bytes = bundle.public().as_bytes();
            let signed = signing_key.sign(&pubkey_bytes);

            key_bundles.push(SignedMessageKeyBundle {
                bundle: bundle,
                selfsig: SelfSignature { 0: signed.clone() },
            });
        }
        // (sanity)
        assert_eq!(key_bundles.len(), num_keybundles);

        let session = SessionStorage {
            fpf_key: None,
            nr_key: None,
            fpf_signature: None,
        };

        Self {
            signing_key: KeyPair {
                sk: signing_key,
                pk: verifying_key,
            },
            fetch_key: KeyPair {
                sk: sk_fetch,
                pk: pk_fetch,
            },
            reply_key: KeyPair {
                sk: sk_reply,
                pk: pk_reply,
            },
            message_keys: key_bundles,
            self_signature: s,
            signed_longterm_key_bytes: selfsigned_pubkeys,
            session_storage: session,
        }
    }

    pub fn public(&self, idx: usize) -> JournalistPublicView {
        let kb = self.message_keys.get(idx).expect("Bad index");
        JournalistPublicView::new(
            self.signing_key.pk,
            self.fetch_key.pk.clone(),
            self.reply_key.pk.clone(),
            self.self_signature,
            self.signed_longterm_key_bytes.clone(),
            (kb.bundle.public(), kb.selfsig),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_initialize_with_passphrase() {
        // Fixed seed RNG
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let mut passphrase_bytes: [u8; 32] = [0u8; 32];
        let _ = &rng.fill_bytes(&mut passphrase_bytes);

        let source1 = Source::from_passphrase(&passphrase_bytes.clone());
        let source2 = Source::from_passphrase(&passphrase_bytes);

        assert_eq!(
            source1.passphrase, source2.passphrase,
            "Expected identical passphrase"
        );

        // DH keys
        assert_eq!(
            source1.message_keys.dh_akem.pk.as_bytes(),
            source2.message_keys.dh_akem.pk.as_bytes(),
            "DH-AKEM Pubkey should be identical"
        );
        assert_eq!(
            source1.message_keys.dh_akem.sk.as_bytes(),
            source2.message_keys.dh_akem.sk.as_bytes(),
            "DH-AKEM Private Key should be identical"
        );
        assert_ne!(
            *source1.message_keys.dh_akem.sk.as_bytes(),
            [0u8; LEN_DHKEM_DECAPS_KEY]
        );

        // PQ KEM keys
        assert_eq!(
            source1.message_keys.mlkem.pk.as_bytes(),
            source2.message_keys.mlkem.pk.as_bytes(),
            "PQ KEM Encaps Key should be identical"
        );
        assert_eq!(
            source1.message_keys.mlkem.sk.as_bytes(),
            source2.message_keys.mlkem.sk.as_bytes(),
            "PQ KEM Decaps Key should be identical"
        );
        assert_ne!(
            *source1.message_keys.mlkem.sk.as_bytes(),
            [0u8; LEN_MLKEM_DECAPS_KEY]
        );

        // Metadata keys
        assert_eq!(
            source1.message_keys.xwing_md.pk.as_bytes(),
            source2.message_keys.xwing_md.pk.as_bytes(),
            "XWING Encaps Key should be identical"
        );
        assert_eq!(
            source1.message_keys.xwing_md.sk.as_bytes(),
            source2.message_keys.xwing_md.sk.as_bytes(),
            "XWING Decaps Key should be identical"
        );
        assert_ne!(
            *source1.message_keys.xwing_md.sk.as_bytes(),
            [0u8; LEN_XWING_DECAPS_KEY]
        );
    }

    #[test]
    fn test_journalist_setup() {
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let journalist = Journalist::new(&mut rng, 5);
        assert_eq!(journalist.message_keys.len(), 5);
        let skb: Vec<SignedKeyBundlePublic> = journalist.signed_keybundles().collect();
        assert_eq!(journalist.message_keys.len(), skb.len());

        let kbs: Vec<&MessageKeyBundle> = journalist.keybundles().collect();
        assert_eq!(kbs.len(), journalist.message_keys.len());

        for i in 0..kbs.len() {
            assert_eq!(
                journalist.message_keys[i].bundle.dh_akem.sk.as_bytes(),
                kbs[i].dh_akem.sk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.dh_akem.pk.as_bytes(),
                kbs[i].dh_akem.pk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.mlkem.sk.as_bytes(),
                kbs[i].mlkem.sk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.mlkem.pk.as_bytes(),
                kbs[i].mlkem.pk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.xwing_md.sk.as_bytes(),
                kbs[i].xwing_md.sk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.xwing_md.pk.as_bytes(),
                kbs[i].xwing_md.pk.as_bytes()
            );
        }
    }

    #[test]
    fn test_journalist_enroll_selfsig() {
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let journalist = Journalist::new(&mut rng, 5);

        let e = journalist.enroll();
        journalist
            .signing_key()
            .verify(&e.bundle.0, &e.selfsig.0)
            .expect("Need correct enrollment sig");
    }
}
