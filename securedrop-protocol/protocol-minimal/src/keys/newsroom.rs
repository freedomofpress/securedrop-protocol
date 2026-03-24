use rand_core::{CryptoRng, RngCore};

use crate::sign::{Domain, SigningKey, VerifyingKey};

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

    /// Get the verification key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.vk
    }

    /// Sign `msg` in the given [`Domain`] using the newsroom signing key.
    pub fn sign(&self, domain: Domain, msg: &[u8]) -> crate::Signature {
        self.sk.sign(domain, msg)
    }
}
