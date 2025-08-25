use rand_core::{CryptoRng, RngCore};

// TODO: These names are kinda bad
use crate::primitives::{DHPrivateKey, DHPublicKey, PPKPrivateKey, PPKPublicKey};
use crate::sign::{Signature, SigningKey, VerifyingKey};

/// Journalists signing key pair
/// Signed by the newsroom
/// Long-term
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
}

/// Journalist fetching key pair
/// Signed by the newsroom
/// Medium-term
pub struct JournalistFetchKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

impl JournalistFetchKeyPair {
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> JournalistFetchKeyPair {
        // TODO: Implement DH key generation when primitives are available
        unimplemented!("DH key generation not yet implemented")
    }
}

/// Journalist long term DH-AKEM keypair
/// Signed by the newsroom
pub struct JournalistDHKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

impl JournalistDHKeyPair {
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> JournalistDHKeyPair {
        // TODO: Implement DH key generation when primitives are available
        unimplemented!("DH key generation not yet implemented")
    }
}

/// Journalist ephemeral KEM key pair
/// Signed by the journalist signing key
pub struct JournalistEphemeralKEMKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

impl JournalistEphemeralKEMKeyPair {
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> JournalistEphemeralKEMKeyPair {
        // TODO: Implement PPK key generation when primitives are available
        unimplemented!("PPK key generation not yet implemented")
    }
}

/// Journalist ephemeral PKE key pair
/// Signed by the journalist signing key
pub struct JournalistEphemeralPKEKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

impl JournalistEphemeralPKEKeyPair {
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> JournalistEphemeralPKEKeyPair {
        // TODO: Implement PPK key generation when primitives are available
        unimplemented!("PPK key generation not yet implemented")
    }
}

/// Journalist ephemeral DH-AKEM keypair
/// Signed by the journalist signing key
pub struct JournalistEphemeralDHKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

impl JournalistEphemeralDHKeyPair {
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> JournalistEphemeralDHKeyPair {
        // TODO: Implement DH key generation when primitives are available
        unimplemented!("DH key generation not yet implemented")
    }
}

// TODO(ro): Fill in types here

// (new) 0.3 Keys

/// Journalist message encryption PSK (used for PQ secret)
///
/// One-time key
///
/// $J_epq$ in the specification.
pub struct JournalistOneTimeMessagePQKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

/// Journalist message encryption keypair
///
/// One-time key
///
/// $J_epke$ in the specification.
pub struct JournalistOneTimeMessageClassicalKeyPair {
    // TODO(ro): Fill in types here from primitives module
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

/// Journalist metadata keypair
///
/// One-time key
///
/// $J_emd$ in the specification.
pub struct JournalistOneTimeMetadataKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

/// Ephemeral key set for a journalist (0.2)
#[derive(Debug, Clone)]
pub struct JournalistEphemeralKeyBundle {
    /// Ephemeral DH public key for DH-AKEM
    pub edh_pk: DHPublicKey,
    /// Ephemeral PPK public key for KEM
    pub ekem_pk: PPKPublicKey,
    /// Ephemeral PPK public key for PKE
    pub epke_pk: PPKPublicKey,
    /// Journalist's signature over the ephemeral keys
    pub signature: Signature,
}

/// Journalist enrollment key bundle
///
/// This bundle is used to enroll a journalist into the system.
/// It contains the journalist's signing, fetching, and DH keys.
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
