use rand_core::{CryptoRng, RngCore};

// From: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_PRIVATE_KEY_LEN: usize = 32;

/// XWING public key.
#[derive(Debug, Clone)]
pub struct XWingPublicKey([u8; XWING_PUBLIC_KEY_LEN]);

/// XWING private key.
#[derive(Debug, Clone)]
pub struct XWingPrivateKey([u8; XWING_PRIVATE_KEY_LEN]);

impl XWingPublicKey {
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; XWING_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl XWingPrivateKey {
    /// Get the private key as bytes
    pub fn as_bytes(&self) -> &[u8; XWING_PRIVATE_KEY_LEN] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; XWING_PRIVATE_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// Generate a new XWING keypair using libcrux_kem
pub fn generate_xwing_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(XWingPrivateKey, XWingPublicKey), anyhow::Error> {
    use libcrux_kem::{Algorithm, key_gen};

    // Generate XWING keypair using libcrux_kem
    let (sk, pk) = key_gen(Algorithm::XWingKemDraft06, rng)
        .map_err(|e| anyhow::anyhow!("XWING key generation failed: {:?}", e))?;

    // Convert to our types
    let private_key_bytes = sk.encode();
    let public_key_bytes = pk.encode();

    // Validate key sizes (XWING should have consistent sizes)
    if private_key_bytes.len() != XWING_PRIVATE_KEY_LEN
        || public_key_bytes.len() != XWING_PUBLIC_KEY_LEN
    {
        return Err(anyhow::anyhow!(
            "Unexpected XWING key sizes: private={}, public={}",
            private_key_bytes.len(),
            public_key_bytes.len()
        ));
    }

    let private_key = XWingPrivateKey::from_bytes(
        private_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert private key bytes"))?,
    );
    let public_key = XWingPublicKey::from_bytes(
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
    fn test_xwing_key_generation() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (private_key, public_key) =
            generate_xwing_keypair(&mut rng).expect("Should generate XWING keypair");
    }

    #[test]
    fn test_xwing_key_serialization() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (private_key, public_key) =
            generate_xwing_keypair(&mut rng).expect("Should generate XWING keypair");

        // Test round-trip serialization
        let private_bytes = *private_key.as_bytes();
        let public_bytes = *public_key.as_bytes();

        let reconstructed_private = XWingPrivateKey::from_bytes(private_bytes);
        let reconstructed_public = XWingPublicKey::from_bytes(public_bytes);

        assert_eq!(private_key.as_bytes(), reconstructed_private.as_bytes());
        assert_eq!(public_key.as_bytes(), reconstructed_public.as_bytes());
    }
}
