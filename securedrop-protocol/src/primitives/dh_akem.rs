use rand_core::{CryptoRng, RngCore};

use crate::client::ClientPrivate;

pub const DH_AKEM_PUBLIC_KEY_LEN: usize = 32;
pub const DH_AKEM_PRIVATE_KEY_LEN: usize = 32;
pub const DH_AKEM_SECRET_LEN: usize = 32;

/// An DH-AKEM public key.
#[derive(Debug, Clone)]
pub struct DhAkemPublicKey([u8; DH_AKEM_PUBLIC_KEY_LEN]);

/// An DH-AKEM private key.
#[derive(Debug, Clone)]
pub struct DhAkemPrivateKey([u8; DH_AKEM_PRIVATE_KEY_LEN]);

/// An DH-AKEM shared secret.
#[derive(Debug, Clone)]
pub struct DhAkemSecret([u8; DH_AKEM_SECRET_LEN]);

impl DhAkemPublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8; DH_AKEM_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl DhAkemPrivateKey {
    /// Get the private key as bytes
    pub fn as_bytes(&self) -> &[u8; DH_AKEM_PRIVATE_KEY_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; DH_AKEM_PRIVATE_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl DhAkemSecret {
    /// Get the shared secret as bytes
    pub fn as_bytes(&self) -> &[u8; DH_AKEM_SECRET_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; DH_AKEM_SECRET_LEN]) -> Self {
        Self(bytes)
    }
}

/// Clamp a scalar to ensure it's a valid X25519 scalar.
fn clamp(scalar: &mut [u8; 32]) {
    // Clear the 3 least significant bits of the first byte
    scalar[0] &= 248u8;
    // Clear the most significant bit of the last byte
    scalar[31] &= 127u8;
    // Set the second most significant bit of the last byte
    scalar[31] |= 64u8;
}

/// Generate DH-AKEM keypair from external randomness
/// FOR TEST PURPOSES ONLY
pub fn deterministic_keygen(
    randomness: [u8; 32],
) -> Result<(DhAkemPrivateKey, DhAkemPublicKey), anyhow::Error> {
    use libcrux_kem::{Algorithm, key_gen_derand};

    // Note that the key_gen_derand function expects the seed to be a valid scalar for X25519
    let mut clamped_randomness = randomness.clone();
    clamp(&mut clamped_randomness);

    let (sk, pk) = key_gen_derand(Algorithm::X25519, &clamped_randomness)
        .map_err(|e| anyhow::anyhow!("DH-AKEM deterministic key generation failed: {:?}", e))?;

    // Convert to our types
    let private_key_bytes = sk.encode();
    let public_key_bytes = pk.encode();

    // Validate key sizes (X25519 should have consistent sizes)
    if private_key_bytes.len() != DH_AKEM_PRIVATE_KEY_LEN
        || public_key_bytes.len() != DH_AKEM_PUBLIC_KEY_LEN
    {
        return Err(anyhow::anyhow!(
            "Unexpected DH-AKEM key sizes: private={}, public={}",
            private_key_bytes.len(),
            public_key_bytes.len()
        ));
    }

    let private_key = DhAkemPrivateKey::from_bytes(
        private_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert private key bytes"))?,
    );
    let public_key = DhAkemPublicKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert public key bytes"))?,
    );

    Ok((private_key, public_key))
}

/// Generate a new DH-AKEM key pair using libcrux_kem
pub fn generate_dh_akem_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(DhAkemPrivateKey, DhAkemPublicKey), anyhow::Error> {
    use libcrux_kem::{Algorithm, key_gen};

    // Generate DH-AKEM keypair using libcrux_kem with X25519
    let (sk, pk) = key_gen(Algorithm::X25519, rng)
        .map_err(|e| anyhow::anyhow!("DH-AKEM key generation failed: {:?}", e))?;

    // Convert to our types
    let private_key_bytes = sk.encode();
    let public_key_bytes = pk.encode();

    // Validate key sizes (X25519 should have consistent 32-byte sizes)
    if private_key_bytes.len() != DH_AKEM_PRIVATE_KEY_LEN
        || public_key_bytes.len() != DH_AKEM_PUBLIC_KEY_LEN
    {
        return Err(anyhow::anyhow!(
            "Unexpected DH-AKEM key sizes: private={}, public={}",
            private_key_bytes.len(),
            public_key_bytes.len()
        ));
    }

    let private_key = DhAkemPrivateKey::from_bytes(
        private_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert private key bytes"))?,
    );
    let public_key = DhAkemPublicKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert public key bytes"))?,
    );

    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_dh_akem_key_generation() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (private_key, public_key) =
            generate_dh_akem_keypair(&mut rng).expect("Should generate DH-AKEM keypair");

        // Verify key sizes
        assert_eq!(private_key.as_bytes().len(), DH_AKEM_PRIVATE_KEY_LEN);
        assert_eq!(public_key.as_bytes().len(), DH_AKEM_PUBLIC_KEY_LEN);

        // Verify keys are different
        assert_ne!(private_key.as_bytes(), public_key.as_bytes());
    }

    #[test]
    fn test_dh_akem_key_serialization() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (private_key, public_key) =
            generate_dh_akem_keypair(&mut rng).expect("Should generate DH-AKEM keypair");

        // Test round-trip serialization
        let private_bytes = *private_key.as_bytes();
        let public_bytes = *public_key.as_bytes();

        let reconstructed_private = DhAkemPrivateKey::from_bytes(private_bytes);
        let reconstructed_public = DhAkemPublicKey::from_bytes(public_bytes);

        assert_eq!(private_key.as_bytes(), reconstructed_private.as_bytes());
        assert_eq!(public_key.as_bytes(), reconstructed_public.as_bytes());
    }

    #[test]
    fn test_deterministic_keygen() {
        proptest!(|(randomness in proptest::array::uniform32(any::<u8>()).prop_filter("exclude zero", |arr| arr != &[0u8; 32]))| {
            let (private_key, public_key) = deterministic_keygen(randomness.try_into().unwrap()).unwrap();
        });
    }
}
