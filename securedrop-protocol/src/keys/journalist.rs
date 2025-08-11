use rand_core::{CryptoRng, RngCore};

// TODO: These names are kinda bad
use crate::primitives::{DHPrivateKey, DHPublicKey, PPKPrivateKey, PPKPublicKey};
use crate::sign::{SigningKey, VerifyingKey};

/// Journalists signing key pair
/// Signed by the newsroom
pub struct JournalistSigningKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}

impl JournalistSigningKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistSigningKeyPair {
        unimplemented!()
    }
}

/// Journalist fetching key pair
/// Signed by the newsroom
pub struct JournalistFetchKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

impl JournalistFetchKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistFetchKeyPair {
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
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistDHKeyPair {
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
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralKEMKeyPair {
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
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralPKEKeyPair {
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
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralDHKeyPair {
        unimplemented!()
    }
}
