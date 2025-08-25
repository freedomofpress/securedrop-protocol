use anyhow::Error;
use libcrux_curve25519::{DK_LEN as SK_LEN, EK_LEN as PK_LEN};
use libcrux_traits::kem::arrayref::Kem;
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub struct PPKPrivateKey;

#[derive(Debug, Clone)]
pub struct PPKPublicKey;

impl PPKPublicKey {
    pub fn into_bytes(self) -> [u8; 32] {
        // TODO: Implement when actual PPK types are available
        [0u8; 32]
    }
}

#[derive(Debug, Clone)]
pub struct DHPublicKey([u8; PK_LEN]);

impl DHPublicKey {
    pub fn into_bytes(self) -> [u8; PK_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; PK_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone)]
pub struct DHPrivateKey([u8; SK_LEN]);

impl DHPrivateKey {
    pub fn into_bytes(self) -> [u8; SK_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; SK_LEN]) -> Self {
        Self(bytes)
    }
}

/// Generate a new DH key pair using X25519
pub fn generate_dh_keypair<R: RngCore + CryptoRng>(
    mut rng: R,
) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);

    let mut public_key = [0u8; PK_LEN];
    let mut secret_key = [0u8; SK_LEN];

    // Generate the key pair using X25519 from libcrux
    // Parameters: ek (public key), dk (secret key), rand (randomness)
    libcrux_curve25519::X25519::keygen(&mut public_key, &mut secret_key, &randomness)
        .map_err(|_| anyhow::anyhow!("X25519 key generation failed"))?;

    Ok((DHPrivateKey(secret_key), DHPublicKey(public_key)))
}
