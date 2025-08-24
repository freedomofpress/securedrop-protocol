use anyhow::Error;
use core::ops::DerefMut;
use libcrux_ed25519::{SigningKey as LibCruxSigningKey, VerificationKey as LibCruxVerifyingKey};
use rand_core::{CryptoRng, RngCore};

/// An Ed25519 signing key.
pub struct SigningKey {
    pub vk: VerifyingKey,
    sk: LibCruxSigningKey,
}

/// An Ed25519 verification key.
#[derive(Copy, Clone)]
pub struct VerifyingKey(LibCruxVerifyingKey);

/// An Ed25519 signature.
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 64]);

impl SigningKey {
    /// Generate a signing key from the supplied `rng`.
    pub fn new(mut rng: &mut impl CryptoRng) -> Result<SigningKey, Error> {
        let (sk, vk) = libcrux_ed25519::generate_key_pair(&mut rng)
            .map_err(|_| anyhow::anyhow!("Key generation failed"))?;

        Ok(SigningKey {
            vk: VerifyingKey(vk),
            sk,
        })
    }

    /// Create a signature on `msg` using this `SigningKey`.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let signature_bytes = libcrux_ed25519::sign(msg, self.sk.as_ref())
            .expect("Signing should not fail with valid key");
        Signature(signature_bytes)
    }
}

impl VerifyingKey {
    /// Get the raw bytes of this verification key
    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    /// Verify a signature on `msg` using this `VerifyingKey`
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        libcrux_ed25519::verify(msg, self.0.as_ref(), &signature.0)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::rng;

    proptest! {
        #[test]
        fn test_sign_verify_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let signature = signing_key.sign(&msg);

            assert!(signing_key.vk.verify(&msg, &signature).is_ok());
        }
    }

    proptest! {
        #[test]
        fn test_verify_fails_with_wrong_message(
            msg1 in proptest::collection::vec(any::<u8>(), 0..100),
            msg2 in proptest::collection::vec(any::<u8>(), 0..100)
        ) {
            if msg1 == msg2 {
                return Ok(());
            }

            let mut rng = rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let signature = signing_key.sign(&msg1);

            assert!(signing_key.vk.verify(&msg2, &signature).is_err());
        }
    }

    proptest! {
        #[test]
        fn test_verify_fails_with_wrong_key(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = rng();
            let key1 = SigningKey::new(&mut rng).unwrap();
            let key2 = SigningKey::new(&mut rng).unwrap();
            let signature = key1.sign(&msg);

            assert!(key2.vk.verify(&msg, &signature).is_err());
        }
    }
}
