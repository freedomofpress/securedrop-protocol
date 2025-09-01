use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

/// An DH-AKEM public key.
#[derive(Debug, Clone)]
pub struct DhAkemPublicKey([u8; 32]);

/// An DH-AKEM private key.
#[derive(Debug, Clone)]
pub struct DhAkemPrivateKey([u8; 32]);

/// An DH-AKEM shared secret.
#[derive(Debug, Clone)]
pub struct DhAkemSecret([u8; 32]);

/// Generate a new DH-AKEM key pair
pub fn generate_dh_akem_keypair<R: RngCore + CryptoRng>(
    mut rng: R,
) -> Result<(DhAkemPrivateKey, DhAkemPublicKey), Error> {
    unimplemented!()
    // HPKE: with https://docs.rs/hpke-rs/latest/hpke_rs/hpke_types/enum.KemAlgorithm.html
    // KemAlgorithm::DhKem25519 ?
}
