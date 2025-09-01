use rand_core::{CryptoRng, RngCore};

const DH_AKEM_PUBLIC_KEY_LEN: usize = 32;
const DH_AKEM_PRIVATE_KEY_LEN: usize = 32;
const DH_AKEM_SECRET_LEN: usize = 32;

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
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_dh_akem_key_generation() {
        let mut rng = StdRng::seed_from_u64(42);

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
        let mut rng = StdRng::seed_from_u64(42);

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
}
