use rand_core::{CryptoRng, RngCore};

use crate::sign::{DomainTag, Signature, SigningKey, VerifyingKey};

/// Newsroom keypair used for signing.
pub struct NewsroomKeyPair {
    vk: VerifyingKey,
    sk: SigningKey,
}

impl core::fmt::Debug for NewsroomKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redacts secret key
        f.debug_struct("NewsroomKeyPair")
            .field("vk", &self.vk)
            .finish_non_exhaustive()
    }
}

impl NewsroomKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, anyhow::Error> {
        let sk = SigningKey::new(&mut rng)?;
        let vk = sk.vk;
        Ok(Self { sk, vk })
    }

    /// Returns the verification key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.vk
    }

    /// Sign `msg` in domain `D` using the newsroom signing key.
    pub fn sign<D: DomainTag>(&self, msg: &[u8]) -> Signature<D> {
        self.sk.sign(msg)
    }
}
