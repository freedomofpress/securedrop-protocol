mod newsroom;

use rand_core::{CryptoRng, RngCore};

use crate::sign::{
    DomainTag, FpfOnNewsroom, JournalistEphemeralKey, JournalistLongTermKey, Signature, SigningKey,
    VerifyingKey,
};

use crate::message::{MessageKeyPair, MessagePublicKey};
use crate::metadata::{MetadataKeyPair, MetadataPublicKey};
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use alloc::vec::Vec;

use crate::constants::*;

/// Generic KeyPair
pub struct KeyPair<SK, PK> {
    pub(crate) sk: SK,
    pub(crate) pk: PK,
}

// silly name but include "fetch" for disambiguation with dh-akem.
// eventually: ristretto255
pub type DhFetchKeyPair = KeyPair<DHPrivateKey, DHPublicKey>;
pub type SigningKeyPair = KeyPair<SigningKey, VerifyingKey>;

/// The public half of an ephemeral key bundle together with the journalist's
/// self-signature over it.
pub type SignedKeyBundlePublic = (KeyBundlePublic, Signature<JournalistEphemeralKey>);

/// The public keys that make up one ephemeral key bundle
#[derive(Debug, Clone)]
pub struct KeyBundlePublic {
    /// SD-APKE ephemeral key `pk_{J,i}^{APKE_E} = (pk1, pk2)`.
    pub apke_pk: MessagePublicKey,
    /// SD-PKE ephemeral key, used for metadata protection.
    pub metadata_pk: MetadataPublicKey,
}

impl KeyBundlePublic {
    /// Serialize the bundle public keys in canonical byte order for signing.
    ///
    /// Layout: `pk_{J,i}^{APKE_E}(DHKEM) || pk_{J,i}^{APKE_E}(ML-KEM) || pk_{J,i}^{PKE_E}(X-Wing)`
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.apke_pk.as_bytes());
        out.extend(self.metadata_pk.as_bytes());
        out
    }
}

pub(crate) struct MessageKeyBundle {
    pub(crate) apke: MessageKeyPair,
    pub(crate) metadata_kp: MetadataKeyPair,
}

impl MessageKeyBundle {
    pub fn new(apke: MessageKeyPair, metadata_kp: MetadataKeyPair) -> Self {
        Self { apke, metadata_kp }
    }

    pub(crate) fn public(&self) -> KeyBundlePublic {
        KeyBundlePublic {
            apke_pk: self.apke.public_key().clone(),
            metadata_pk: self.metadata_kp.public_key().clone(),
        }
    }
}

pub(crate) struct SignedMessageKeyBundle {
    pub(crate) bundle: MessageKeyBundle,
    pub(crate) selfsig: Signature<JournalistEphemeralKey>,
}

#[derive(Debug, Clone)]
pub struct SignedLongtermPubKeyBytes(
    pub [u8; LEN_DHKEM_ENCAPS_KEY + LEN_MLKEM_ENCAPS_KEY + LEN_DH_ITEM],
);

impl SignedLongtermPubKeyBytes {
    /// Serialize long-term public keys into the canonical byte encoding.
    ///
    /// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
    /// where `pk_J^APKE = pk_J^AKEM (DH-AKEM) || pk_J^PQ (ML-KEM)`
    pub(crate) fn from_keys(reply_apke: &MessagePublicKey, fetch_pk: &DHPublicKey) -> Self {
        let mut pubkey_bytes = [0u8; LEN_DHKEM_ENCAPS_KEY + LEN_MLKEM_ENCAPS_KEY + LEN_DH_ITEM];
        let mut offset = 0;
        pubkey_bytes[offset..offset + LEN_DHKEM_ENCAPS_KEY]
            .copy_from_slice(reply_apke.dhakem.as_bytes());
        offset += LEN_DHKEM_ENCAPS_KEY;
        pubkey_bytes[offset..offset + LEN_MLKEM_ENCAPS_KEY]
            .copy_from_slice(reply_apke.mlkem.as_bytes());
        offset += LEN_MLKEM_ENCAPS_KEY;
        pubkey_bytes[offset..].copy_from_slice(&fetch_pk.into_bytes());

        Self(pubkey_bytes)
    }

    /// Return the canonical byte encoding of the long-term public keys.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Enrollment {
    pub bundle: SignedLongtermPubKeyBytes,
    pub selfsig: Signature<JournalistLongTermKey>,
    pub keys: (VerifyingKey, DHPublicKey, MessagePublicKey),
}

// in memory session storage
pub struct SessionStorage {
    pub fpf_key: Option<VerifyingKey>,
    pub nr_key: Option<VerifyingKey>,
    pub fpf_signature: Option<Signature<FpfOnNewsroom>>,
}

/// A key pair for FPF (Freedom of the Press Foundation).
pub struct FPFKeyPair {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl core::fmt::Debug for FPFKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FPFKeyPair")
            .field("vk", &self.vk)
            .finish_non_exhaustive()
    }
}

impl FPFKeyPair {
    /// Generate a new FPF key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the key generation fails.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, anyhow::Error> {
        let sk = SigningKey::new(&mut rng)?;
        let vk = sk.vk;
        Ok(Self { sk, vk })
    }

    /// Returns the verification key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.vk
    }

    /// Sign `msg` in domain `D` using the FPF signing key.
    pub fn sign<D: DomainTag>(&self, msg: &[u8]) -> Signature<D> {
        self.sk.sign(msg)
    }
}

pub use newsroom::NewsroomKeyPair;
