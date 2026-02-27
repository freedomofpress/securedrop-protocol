use anyhow::Error;
use libcrux_curve25519::ecdh;
use libcrux_traits::kem::arrayref::Kem;
use rand_core::{CryptoRng, RngCore};

pub use libcrux_curve25519::{DK_LEN as SK_LEN, EK_LEN as PK_LEN};

/// An X25519 public key.
#[derive(Debug, Clone, Copy)]
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

/// Generate DH keypair from external randomness
/// FOR TEST PURPOSES ONLY
pub fn deterministic_dh_keygen(randomness: [u8; 32]) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    let mut public_key = [0u8; PK_LEN];
    let mut secret_key = [0u8; SK_LEN];

    libcrux_curve25519::X25519::keygen(&mut public_key, &mut secret_key, &randomness)
        .map_err(|_| anyhow::anyhow!("X25519 key generation failed"))?;

    Ok((DHPrivateKey(secret_key), DHPublicKey(public_key)))
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

    typed(secret_key, public_key)
}

fn typed(sk: [u8; SK_LEN], pk: [u8; PK_LEN]) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    Ok((DHPrivateKey(sk), DHPublicKey(pk)))
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
    ecdh(&mut shared_secret_bytes, &public_key.0, &private_scalar)
        .map_err(|_| anyhow::anyhow!("X25519 DH failed"))?;
    Ok(DHSharedSecret(shared_secret_bytes))
}

#[cfg(test)]
mod tests {
    use crate::encrypt_decrypt::LEN_DH_ITEM;

    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    // Toy purposes
    fn get_rng() -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS random source failed");
        ChaCha20Rng::from_seed(seed)
    }

    #[test]
    fn test_deterministic_dh_keygen() {
        proptest!(|(randomness in proptest::array::uniform32(any::<u8>()))| {
            let (private_key, public_key) = deterministic_dh_keygen(randomness).unwrap();
        });
    }

    #[test]
    fn test_dh_shared_secret() {
        let mut rng = get_rng();

        let (sk1, pk1) = generate_dh_keypair(&mut rng).expect("need dh keygen");

        let (sk2, pk2) = generate_dh_keypair(&mut rng).expect("need dh keygen");

        let ss1 = dh_shared_secret(&pk1, sk2.into_bytes()).expect("need shared secret 1");
        let ss2 = dh_shared_secret(&pk2, sk1.into_bytes()).expect("need shared secret 2");

        assert_eq!(ss1.clone().into_bytes(), ss2.into_bytes());
        assert_ne!(ss1.into_bytes(), [0u8; LEN_DH_ITEM])
    }
}
