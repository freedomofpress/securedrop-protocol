use rand::{CryptoRng, RngCore};

use crate::sign::{SigningKey, VerifyingKey};

/// Newsroom keypair used for signing.
///
/// TODO: Make the signing key private.
pub struct NewsroomKeyPair {
    pub vk: VerifyingKey,
    pub sk: SigningKey,
}

impl NewsroomKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> NewsroomKeyPair {
        let sk = SigningKey::new(&mut rng).unwrap();
        let vk = sk.vk;
        NewsroomKeyPair { sk, vk }
    }
}

