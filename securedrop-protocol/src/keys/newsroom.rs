use rand::{CryptoRng, RngCore};

use crate::sign::{SigningKey, VerifyingKey};

/// Newsroom keypair used for signing.
pub struct NewsroomKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}

impl NewsroomKeyPair {
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> NewsroomKeyPair {
        unimplemented!()
    }
}
