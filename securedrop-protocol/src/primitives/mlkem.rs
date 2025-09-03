use rand_core::{CryptoRng, RngCore};

// From NIST ML-KEM spec:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
// See Table 2 which shows k = 3 for ML-KEM-768 and
// Algorithm 19 which defines the size of the encap and decap keys in terms of k
pub const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
pub const MLKEM768_PRIVATE_KEY_LEN: usize = 2400;

/// MLKEM-768 public key.
#[derive(Debug, Clone)]
pub struct MLKEM768PublicKey([u8; MLKEM768_PUBLIC_KEY_LEN]);

/// MLKEM-768 private key.
#[derive(Debug, Clone)]
pub struct MLKEM768PrivateKey([u8; MLKEM768_PRIVATE_KEY_LEN]);

impl MLKEM768PublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; MLKEM768_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl MLKEM768PrivateKey {
    /// Get the private key as bytes
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PRIVATE_KEY_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; MLKEM768_PRIVATE_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// Generate MLKEM-768 keypair from external randomness
/// FOR TEST PURPOSES ONLY
pub fn deterministic_keygen(
    randomness: [u8; 32],
) -> Result<(MLKEM768PrivateKey, MLKEM768PublicKey), anyhow::Error> {
    use libcrux_kem::{Algorithm, key_gen_derand};

    // Generate MLKEM-768 keypair using libcrux_kem with deterministic randomness
    let (sk, pk) = key_gen_derand(Algorithm::MlKem768, &randomness)
        .map_err(|e| anyhow::anyhow!("MLKEM-768 deterministic key generation failed: {:?}", e))?;

    // Convert to our types
    let private_key_bytes = sk.encode();
    let public_key_bytes = pk.encode();

    // Validate key sizes (MLKEM-768 should have consistent sizes)
    if private_key_bytes.len() != MLKEM768_PRIVATE_KEY_LEN
        || public_key_bytes.len() != MLKEM768_PUBLIC_KEY_LEN
    {
        return Err(anyhow::anyhow!(
            "Unexpected MLKEM-768 key sizes: private={}, public={}",
            private_key_bytes.len(),
            public_key_bytes.len()
        ));
    }

    let private_key = MLKEM768PrivateKey::from_bytes(
        private_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert private key bytes"))?,
    );
    let public_key = MLKEM768PublicKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert public key bytes"))?,
    );

    Ok((private_key, public_key))
}

/// Generate a new MLKEM-768 keypair using libcrux_kem
pub fn generate_mlkem768_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(MLKEM768PrivateKey, MLKEM768PublicKey), anyhow::Error> {
    use libcrux_kem::{Algorithm, key_gen};

    // Generate MLKEM-768 keypair using libcrux_kem
    let (sk, pk) = key_gen(Algorithm::MlKem768, rng)
        .map_err(|e| anyhow::anyhow!("MLKEM-768 key generation failed: {:?}", e))?;

    // Convert to our types
    let private_key_bytes = sk.encode();
    let public_key_bytes = pk.encode();

    // Validate key sizes (MLKEM-768 should have consistent sizes)
    if private_key_bytes.len() != MLKEM768_PRIVATE_KEY_LEN
        || public_key_bytes.len() != MLKEM768_PUBLIC_KEY_LEN
    {
        return Err(anyhow::anyhow!(
            "Unexpected MLKEM-768 key sizes: private={}, public={}",
            private_key_bytes.len(),
            public_key_bytes.len()
        ));
    }

    let private_key = MLKEM768PrivateKey::from_bytes(
        private_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert private key bytes"))?,
    );
    let public_key = MLKEM768PublicKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert public key bytes"))?,
    );

    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_mlkem768_key_generation() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (private_key, public_key) =
            generate_mlkem768_keypair(&mut rng).expect("Should generate MLKEM-768 keypair");

        // Verify key sizes
        assert_eq!(private_key.as_bytes().len(), MLKEM768_PRIVATE_KEY_LEN);
        assert_eq!(public_key.as_bytes().len(), MLKEM768_PUBLIC_KEY_LEN);

        // Verify keys are different (they have different sizes anyway)
        assert_ne!(private_key.as_bytes().len(), public_key.as_bytes().len());
    }

    #[test]
    fn test_mlkem768_key_serialization() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (private_key, public_key) =
            generate_mlkem768_keypair(&mut rng).expect("Should generate MLKEM-768 keypair");

        // Test round-trip serialization
        let private_bytes = *private_key.as_bytes();
        let public_bytes = *public_key.as_bytes();

        let reconstructed_private = MLKEM768PrivateKey::from_bytes(private_bytes);
        let reconstructed_public = MLKEM768PublicKey::from_bytes(public_bytes);

        assert_eq!(private_key.as_bytes(), reconstructed_private.as_bytes());
        assert_eq!(public_key.as_bytes(), reconstructed_public.as_bytes());
    }
}
