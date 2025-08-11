use rand_core::{CryptoRng, RngCore};

use crate::primitives::{DHPrivateKey, DHPublicKey, PPKPrivateKey, PPKPublicKey};

// TODO: Name these better

#[derive(Debug, Clone)]
pub struct SourceKeyBundle {
    pub fetch: SourceFetchKeyPair,
    pub long_term_dh: SourceDHKeyPair,
    pub kem: SourceKEMKeyPair,
    pub pke: SourcePKEKeyPair,
}

pub struct SourcePassphrase {}

#[derive(Debug, Clone)]
pub struct SourceFetchKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

#[derive(Debug, Clone)]
pub struct SourceDHKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

#[derive(Debug, Clone)]
pub struct SourceKEMKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

#[derive(Debug, Clone)]
pub struct SourcePKEKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

/// Generate a passphrase and the corresponding keys (via KDF).
impl SourceKeyBundle {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> (SourcePassphrase, SourceKeyBundle) {
        unimplemented!()
    }
}
