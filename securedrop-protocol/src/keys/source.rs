use rand_core::{CryptoRng, RngCore};

use crate::primitives::{DHPrivateKey, DHPublicKey, PPKPrivateKey, PPKPublicKey};

// TODO: Name these better

pub struct SourceKeyBundle {
    pub fetch: SourceFetchKeyPair,
    pub long_term_dh: SourceDHKeyPair,
    pub kem: SourceKEMKeyPair,
    pub pke: SourcePKEKeyPair,
}

pub struct SourcePassphrase {}

struct SourceFetchKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

struct SourceDHKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

struct SourceKEMKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

struct SourcePKEKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

/// Generate a passphrase and the corresponding keys (via KDF).
impl SourceKeyBundle {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> (SourcePassphrase, SourceKeyBundle) {
        unimplemented!()
    }
}
