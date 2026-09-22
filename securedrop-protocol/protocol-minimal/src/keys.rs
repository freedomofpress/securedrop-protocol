mod newsroom;

use rand_core::{CryptoRng, RngCore};

use crate::sign::{
    DomainTag, FpfOnNewsroom, JournalistEphemeralKey, JournalistLongTermKey, Signature, SigningKey,
    VerifyingKey,
};

use crate::message::{MessageKeyPair, MessagePublicKey};
use crate::metadata::{MetadataKeyPair, MetadataPublicKey};
use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
use crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN;
use crate::primitives::ristretto255::{DH_PUBLIC_KEY_LEN, DHPrivateKey, DHPublicKey};
use alloc::string::String;
use alloc::vec::Vec;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

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
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
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
        out.extend_from_slice(&self.apke_pk.as_bytes());
        out.extend_from_slice(&self.metadata_pk.as_bytes());
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
pub(crate) struct LongtermKeyBundle {
    pub(crate) apke: MessagePublicKey,
    pub(crate) fetch_pk: DHPublicKey,
}

impl LongtermKeyBundle {
    pub fn new(apke: MessagePublicKey, fetch_pk: DHPublicKey) -> Self {
        Self { apke, fetch_pk }
    }

    /// Serialize long-term public keys into the canonical byte encoding.
    ///
    /// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
    /// where `pk_J^APKE = pk_J^AKEM (DH-AKEM) || pk_J^PQ (ML-KEM)`
    pub fn as_bytes(&self) -> [u8; 1248] {
        let apke_bytes = self.apke.as_bytes();
        let fetch_bytes = self.fetch_pk.into_bytes();

        let mut pubkey_bytes =
            [0u8; DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN + DH_PUBLIC_KEY_LEN];
        pubkey_bytes[..apke_bytes.len()].copy_from_slice(&apke_bytes);
        pubkey_bytes[apke_bytes.len()..].copy_from_slice(&fetch_bytes);

        pubkey_bytes
    }
}

#[derive(Debug, Clone)]
pub struct SignedLongtermKeyBundle {
    pub bundle: LongtermKeyBundle,
    pub selfsig: Signature<JournalistLongTermKey>,
}

impl SignedLongtermKeyBundle {
    pub fn new(bundle: LongtermKeyBundle, selfsig: Signature<JournalistLongTermKey>) -> Self {
        Self { bundle, selfsig }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let bundle_bytes = self.bundle.as_bytes();
        let sig_bytes = self.selfsig.as_bytes();

        let mut pubkey_bytes = Vec::with_capacity(bundle_bytes.len() + sig_bytes.len());
        pubkey_bytes.extend_from_slice(&bundle_bytes);
        pubkey_bytes.extend_from_slice(&sig_bytes);

        pubkey_bytes
    }

    pub fn bundle_bytes(&self) -> [u8; 1248] {
        self.bundle.as_bytes()
    }

    pub fn apke(&self) -> &MessagePublicKey {
        &self.bundle.apke
    }

    pub fn fetch_pk(&self) -> &DHPublicKey {
        &self.bundle.fetch_pk
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl Serialize for SignedLongtermKeyBundle {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.as_bytes()))
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl<'de> Deserialize<'de> for SignedLongtermKeyBundle {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let mut bytes =
            [0u8; DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN + DH_PUBLIC_KEY_LEN + 64];
        hex::decode_to_slice(s.trim(), &mut bytes).map_err(D::Error::custom)?;

        let offset = DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN;
        let apke = MessagePublicKey::from_bytes(&bytes[..offset]).map_err(D::Error::custom)?;
        let mut fetch_key_bytes = [0u8; DH_PUBLIC_KEY_LEN];
        fetch_key_bytes.copy_from_slice(&bytes[offset..offset + DH_PUBLIC_KEY_LEN]);
        let fetch = DHPublicKey::decode(fetch_key_bytes).map_err(D::Error::custom)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&bytes[offset + DH_PUBLIC_KEY_LEN..]);
        Ok(Self {
            bundle: LongtermKeyBundle::new(apke, fetch),
            selfsig: Signature::from_bytes(sig_bytes),
        })
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct Enrollment {
    pub bundle: SignedLongtermKeyBundle,
    // Journalist's long-term verification key, verified out of band.
    pub verification_key: VerifyingKey,
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

// hax struggles with the debug format function signature, but it is
// debug only, so we can exclude it from extraction
#[cfg_attr(hax, hax_lib::exclude)]
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
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, anyhow::Error> {
        let sk = SigningKey::new(rng)?;
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

    /// The FPF signing key used as a secret.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.sk.as_bytes()
    }

    /// Reconstruct an [`FPFKeyPair`] from its secret.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        let sk = SigningKey::from_seed(seed);
        let vk = sk.vk;
        Self { sk, vk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fpf_keypair_seed_roundtrip(seed: [u8; 32]) {
            let kp = FPFKeyPair::from_bytes(seed);
            prop_assert_eq!(kp.as_bytes(), seed);
            let kp2 = FPFKeyPair::from_bytes(kp.as_bytes());
            prop_assert_eq!(
                kp.verifying_key().into_bytes(),
                kp2.verifying_key().into_bytes()
            );
        }
    }
}

pub use newsroom::NewsroomKeyPair;
