use rand_core::{CryptoRng, RngCore};

use crate::primitives::mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey};
use crate::primitives::xwing::{XWingPrivateKey, XWingPublicKey};
use crate::primitives::{
    PPKPrivateKey, PPKPublicKey, dh_akem::DhAkemPrivateKey, dh_akem::DhAkemPublicKey,
    x25519::DHPrivateKey, x25519::DHPublicKey,
};
use crate::sign::{Signature, SigningKey, VerifyingKey};

/// Journalists signing key pair
/// Signed by the newsroom
/// Long-term, same in 0.3
pub struct JournalistSigningKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}

impl JournalistSigningKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistSigningKeyPair {
        let sk = SigningKey::new(&mut rng).unwrap();
        let vk = sk.vk;
        JournalistSigningKeyPair { vk, sk }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sk.sign(message)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// Journalist fetching key pair
/// Signed by the newsroom
/// Medium-term X25519, same in 0.3
#[derive(Clone)]
pub struct JournalistFetchKeyPair {
    pub public_key: DHPublicKey,
    pub(crate) private_key: DHPrivateKey,
}

impl JournalistFetchKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistFetchKeyPair {
        let (private_key, public_key) = crate::primitives::x25519::generate_dh_keypair(&mut rng)
            .expect("DH key generation failed");
        JournalistFetchKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist medium term keypair
/// Signed by the newsroom
///
/// Only used in 0.2
#[deprecated]
#[derive(Clone)]
pub struct JournalistDHKeyPair {
    pub public_key: DHPublicKey,
    pub(crate) private_key: DHPrivateKey,
}

impl JournalistDHKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistDHKeyPair {
        let (private_key, public_key) = crate::primitives::x25519::generate_dh_keypair(&mut rng)
            .expect("DH key generation failed");
        JournalistDHKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral KEM key pair
/// Signed by the journalist signing key
/// Only used in 0.2
#[deprecated]
pub struct JournalistEphemeralKEMKeyPair {
    pub public_key: PPKPublicKey,
    pub(crate) private_key: PPKPrivateKey,
}

impl JournalistEphemeralKEMKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralKEMKeyPair {
        // Temporarily use DH keys as PPK placeholders
        let (dh_private_key, dh_public_key) =
            crate::primitives::x25519::generate_dh_keypair(&mut rng)
                .expect("DH key generation failed");
        let private_key = PPKPrivateKey::new(dh_private_key);
        let public_key = PPKPublicKey::new(dh_public_key);
        JournalistEphemeralKEMKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral PKE key pair
/// Signed by the journalist signing key
/// Only used in 0.2
#[deprecated]
pub struct JournalistEphemeralPKEKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

impl JournalistEphemeralPKEKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralPKEKeyPair {
        // Temporarily use DH keys as PPK placeholders
        let (dh_private_key, dh_public_key) =
            crate::primitives::x25519::generate_dh_keypair(&mut rng)
                .expect("DH key generation failed");
        let private_key = PPKPrivateKey::new(dh_private_key);
        let public_key = PPKPublicKey::new(dh_public_key);
        JournalistEphemeralPKEKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral DH-AKEM keypair
/// Signed by the journalist signing key
/// Only used in 0.2
#[deprecated]
pub struct JournalistEphemeralDHKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

impl JournalistEphemeralDHKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralDHKeyPair {
        let (private_key, public_key) = crate::primitives::x25519::generate_dh_keypair(&mut rng)
            .expect("DH key generation failed");
        JournalistEphemeralDHKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist message encryption PSK (used for PQ secret)
///
/// One-time key
///
/// $J_epq$ in the specification.
#[derive(Clone)]
pub struct JournalistOneTimeMessagePQKeyPair {
    pub public_key: MLKEM768PublicKey,
    pub(crate) private_key: MLKEM768PrivateKey,
}

/// Journalist message encryption keypair
///
/// One-time key
///
/// $J_epke$ in the specification.
#[derive(Clone)]
pub struct JournalistOneTimeMessageClassicalKeyPair {
    pub public_key: DhAkemPublicKey,
    pub(crate) private_key: DhAkemPrivateKey,
}

/// Journalist metadata keypair
///
/// One-time key
///
/// $J_emd$ in the specification.
#[derive(Clone)]
pub struct JournalistOneTimeMetadataKeyPair {
    pub public_key: XWingPublicKey,
    pub(crate) private_key: XWingPrivateKey,
}

/// Ephemeral public keys for a journalist (without signature)
///
/// This struct contains just the ephemeral public keys that need to be signed.
/// Used for creating the message to sign in Step 3.2.
#[deprecated]
#[derive(Debug, Clone)]
pub struct JournalistEphemeralPublicKeys {
    /// Ephemeral DH public key for DH-AKEM
    pub edh_pk: DHPublicKey,
    /// Ephemeral PPK public key for KEM
    pub ekem_pk: PPKPublicKey,
    /// Ephemeral PPK public key for PKE
    pub epke_pk: PPKPublicKey,
}

impl JournalistEphemeralPublicKeys {
    /// Convert the ephemeral public keys to a byte array for signing
    ///
    /// Returns a 96-byte array containing the concatenated public keys:
    /// - edh_pk (32 bytes)
    /// - ekem_pk (32 bytes)
    /// - epke_pk (32 bytes)
    pub fn into_bytes(self) -> [u8; 96] {
        let mut bytes = [0u8; 96];

        // Ephemeral DH public key (32 bytes)
        bytes[0..32].copy_from_slice(&self.edh_pk.into_bytes());

        // Ephemeral KEM public key (32 bytes)
        bytes[32..64].copy_from_slice(&self.ekem_pk.into_bytes());

        // Ephemeral PKE public key (32 bytes)
        bytes[64..96].copy_from_slice(&self.epke_pk.into_bytes());

        bytes
    }
}

/// Ephemeral key set for a journalist
#[deprecated]
#[derive(Debug, Clone)]
pub struct JournalistEphemeralKeyBundle {
    /// The ephemeral public keys
    pub public_keys: JournalistEphemeralPublicKeys,
    /// Journalist's signature over the ephemeral keys
    pub signature: Signature,
}

/// Journalist enrollment key bundle
///
/// This bundle is used to enroll a journalist into the system.
/// It contains the journalist's signing, fetching, and DH keys.
#[deprecated]
#[derive(Clone)]
pub struct JournalistEnrollmentKeyBundle {
    /// Journalist's signing key
    pub signing_key: VerifyingKey,
    /// Journalist's fetching key
    pub fetching_key: DHPublicKey,
    /// Journalist's DH key
    pub dh_key: DHPublicKey,
}

/// a 96 byte array of the required keys for enrollment
impl JournalistEnrollmentKeyBundle {
    pub fn into_bytes(self) -> [u8; 96] {
        let mut bytes = [0u8; 96];

        // Signing key verification key (32 bytes)
        bytes[0..32].copy_from_slice(&self.signing_key.into_bytes());

        // Fetching key public key (32 bytes)
        bytes[32..64].copy_from_slice(&self.fetching_key.into_bytes());

        // DH key public key (32 bytes)
        bytes[64..96].copy_from_slice(&self.dh_key.into_bytes());

        bytes
    }
}

/// Journalist enrollment key bundle for 0.3 spec
///
/// This bundle is used to enroll a journalist into the system.
/// TODO: Rename to JournalistEnrollmentKeyBundle once we delete the old one
#[derive(Clone)]
pub struct JournalistEnrollmentKeyBundle0_3 {
    /// Journalist's signing key
    pub signing_key: VerifyingKey,
    /// Journalist's fetching key
    pub fetching_key: DHPublicKey,
}

impl JournalistEnrollmentKeyBundle0_3 {
    /// Convert the enrollment key bundle to a byte array for signing
    ///
    /// Returns a byte array containing the concatenated public keys:
    /// - signing_key (32 bytes)
    /// - fetching_key (32 bytes)
    /// Total: 64 bytes
    pub fn into_bytes(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        // Signing key verification key (32 bytes)
        bytes[0..32].copy_from_slice(&self.signing_key.into_bytes());

        // Fetching key public key (32 bytes)
        bytes[32..64].copy_from_slice(&self.fetching_key.into_bytes());

        bytes
    }
}
