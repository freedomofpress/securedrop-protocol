/// Abstracts over the signing primitive used.
use rand_core::{CryptoRng, RngCore};

// TODO(jen): Replace with libcrux Ed25519 types

/// A signing key.
#[derive(Copy, Clone)]
pub struct SigningKey {
    vk: VerifyingKey,
}

#[derive(Copy, Clone)]
pub struct VerifyingKey {}

pub struct Signature {}

impl SigningKey {
    /// Generate a signing key from the supplied `rng`.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey {
        unimplemented!()
    }

    /// Create a signature on `msg` using this `SigningKey`.
    pub fn sign<R: RngCore + CryptoRng>(&self, mut rng: R, msg: &[u8]) -> Signature {
        unimplemented!()
    }
}

impl VerifyingKey {
    /// Verify a signature on `msg` using this `VerifyingKey`
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        unimplemented!()
    }
}
