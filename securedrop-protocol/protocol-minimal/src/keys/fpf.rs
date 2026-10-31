use rand_core::{CryptoRng, RngCore};

use crate::sign::{DomainTag, Signature, SigningKey, VerifyingKey};

/// A key pair for FPF (Freedom of the Press Foundation).
pub struct FPFKeyPair {
    sk: SigningKey,
}

// hax struggles with the debug format function signature, but it is
// debug only, so we can exclude it from extraction
#[cfg_attr(hax, hax_lib::exclude)]
impl core::fmt::Debug for FPFKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FPFKeyPair")
            .field("vk", &self.sk.vk)
            .finish_non_exhaustive()
    }
}

impl FPFKeyPair {
    /// Generate a new FPF key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the key generation fails.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, anyhow::Error> {
        let sk = SigningKey::new(rng)?;
        Ok(Self { sk })
    }

    /// Returns the verification key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.sk.vk
    }

    /// Sign `msg` in domain `D` using the FPF signing key.
    pub fn sign<D: DomainTag>(&self, msg: &[u8]) -> Signature<D> {
        self.sk.sign(msg)
    }

    /// The FPF signing key used as a secret.
    pub fn as_bytes(&self) -> [u8; SigningKey::SEED_LEN] {
        self.sk.as_bytes()
    }

    /// Reconstruct an [`FPFKeyPair`] from its secret.
    pub fn from_bytes(seed: [u8; SigningKey::SEED_LEN]) -> Self {
        Self {
            sk: SigningKey::from_seed(seed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fpf_keypair_seed_roundtrip(seed: [u8; SigningKey::SEED_LEN]) {
            let kp = FPFKeyPair::from_bytes(seed);
            prop_assert_eq!(kp.as_bytes(), seed);
            let kp2 = FPFKeyPair::from_bytes(kp.as_bytes());
            prop_assert_eq!(
                kp.verifying_key().into_bytes(),
                kp2.verifying_key().into_bytes()
            );
        }
    }
}
