use rand_core::{CryptoRng, RngCore};

use crate::sign::{DomainTag, Signature, SigningKey, VerifyingKey};

/// Newsroom keypair used for signing.
pub struct NewsroomKeyPair {
    vk: VerifyingKey,
    sk: SigningKey,
}

// hax struggles with the debug format function signature, but it is
// debug only, so we can exclude it from extraction
#[cfg_attr(hax, hax_lib::exclude)]
impl core::fmt::Debug for NewsroomKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redacts secret key
        f.debug_struct("NewsroomKeyPair")
            .field("vk", &self.vk)
            .finish_non_exhaustive()
    }
}

impl NewsroomKeyPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, anyhow::Error> {
        let sk = SigningKey::new(rng)?;
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

    /// The newsroom signing key used as a secret.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.sk.as_bytes()
    }

    /// Reconstruct a [`NewsroomKeyPair`] from its secret.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        let sk = SigningKey::from_seed(seed);
        let vk = sk.vk;
        Self { vk, sk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn newsroom_keypair_seed_roundtrip(seed: [u8; 32]) {
            let kp = NewsroomKeyPair::from_bytes(seed);
            prop_assert_eq!(kp.as_bytes(), seed);
            let kp2 = NewsroomKeyPair::from_bytes(kp.as_bytes());
            prop_assert_eq!(
                kp.verifying_key().into_bytes(),
                kp2.verifying_key().into_bytes()
            );
        }
    }
}
