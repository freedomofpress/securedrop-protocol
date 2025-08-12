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
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> JournalistSigningKeyPair {
        unimplemented!()
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
        unimplemented!()
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
        unimplemented!()
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
        unimplemented!()
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
        unimplemented!()
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
        unimplemented!()
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
