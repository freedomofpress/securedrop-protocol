mod newsroom;

use rand_core::{CryptoRng, RngCore};

use crate::sign::Domain;
use crate::{SigningKey, VerifyingKey};

use crate::SelfSignature;
use crate::Signature;
use crate::primitives::dh_akem::DhAkemPrivateKey;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::mlkem::MLKEM768PrivateKey;
use crate::primitives::mlkem::MLKEM768PublicKey;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::xwing::XWingPrivateKey;
use crate::primitives::xwing::XWingPublicKey;
use alloc::vec::Vec;
use libcrux_sha2::Digest;

use crate::constants::*;

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
    pub(crate) bundle: MessageKeyBundle,
    pub(crate) selfsig: SelfSignature,
}

#[derive(Debug, Clone)]
pub struct SignedLongtermPubKeyBytes(pub [u8; LEN_DHKEM_ENCAPS_KEY + LEN_DH_ITEM]);

impl SignedLongtermPubKeyBytes {
    /// Serialize long-term public keys into the canonical byte encoding.
    ///
    /// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
    pub(crate) fn from_keys(fetch_pk: &DHPublicKey, reply_dhakem: &DhAkemPublicKey) -> Self {
        let mut pubkey_bytes = [0u8; LEN_DHKEM_ENCAPS_KEY + LEN_DH_ITEM];
        pubkey_bytes[0..LEN_DHKEM_ENCAPS_KEY].copy_from_slice(reply_dhakem.as_bytes());
        pubkey_bytes[LEN_DHKEM_ENCAPS_KEY..].copy_from_slice(&fetch_pk.into_bytes());

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
    pub selfsig: SelfSignature,
    pub keys: (VerifyingKey, DHPublicKey, DhAkemPublicKey),
}

// in memory session storage
pub struct SessionStorage {
    pub fpf_key: Option<VerifyingKey>,
    pub nr_key: Option<VerifyingKey>,
    pub fpf_signature: Option<Signature>,
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
    /// Generate a new FPF key pair
    ///
    /// # Errors
    ///
    /// Returns an error if the key generation fails.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, anyhow::Error> {
        let sk = SigningKey::new(&mut rng)?;
        let vk = sk.vk;
        Ok(Self { sk, vk })
    }

    /// Get the verification key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.vk
    }

    /// Sign `msg` in the given [`Domain`] using the FPF signing key.
    pub fn sign(&self, domain: Domain, msg: &[u8]) -> crate::Signature {
        self.sk.sign(domain, msg)
    }
}

pub use newsroom::NewsroomKeyPair;
