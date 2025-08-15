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
    /// Verify a signature on `msg` using this `VerifyingKey`
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        libcrux_ed25519::verify(msg, self.0.as_ref(), &signature.0)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }
}
