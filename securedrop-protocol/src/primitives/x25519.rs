use anyhow::Error;
use libcrux_curve25519::{DK_LEN as SK_LEN, EK_LEN as PK_LEN};
use libcrux_traits::kem::arrayref::Kem;
use rand_core::{CryptoRng, RngCore};

/// An X25519 public key.
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

/// An X25519 private key.
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

/// An X25519 shared secret.
#[derive(Debug, Clone)]
pub struct DHSharedSecret([u8; 32]);

impl DHSharedSecret {
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
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

/// Generate a random scalar for DH operations using X25519
pub fn generate_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Result<[u8; 32], Error> {
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);

    let mut secret_key = [0u8; 32];
    let mut _public_key = [0u8; 32]; // We don't need the public key here

    // Generate the key pair using X25519 from libcrux
    // Parameters: ek (public key), dk (secret key), rand (randomness)
    libcrux_curve25519::X25519::keygen(&mut _public_key, &mut secret_key, &randomness)
        .map_err(|_| anyhow::anyhow!("X25519 key generation failed"))?;

    Ok(secret_key)
}

/// Convert a scalar to a DH public key using the X25519 standard generator base point
///
/// libcrux_curve25519::secret_to_public uses the standard X25519 base point G = 9
/// (defined as [9, 0, 0, 0, ...] in the HACL implementation, see `g25519` in their code)
pub fn dh_public_key_from_scalar(scalar: [u8; 32]) -> DHPublicKey {
    let mut public_key_bytes = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public_key_bytes, &scalar);
    DHPublicKey::from_bytes(public_key_bytes)
}

/// Compute DH shared secret
pub fn dh_shared_secret(
    public_key: &DHPublicKey,
    private_scalar: [u8; 32],
) -> Result<DHSharedSecret, Error> {
    let mut shared_secret_bytes = [0u8; 32];
    libcrux_curve25519::ecdh(&mut shared_secret_bytes, &private_scalar, &public_key.0)
        .map_err(|_| anyhow::anyhow!("X25519 DH failed"))?;
    Ok(DHSharedSecret(shared_secret_bytes))
}
