
use anyhow::Error;
use libcrux_curve25519::{DK_LEN as SK_LEN, EK_LEN as PK_LEN};
use hpke_rs::hpke_types::KemAlgorithm::{XWingDraft06, DhKem25519};
use hpke_rs::HpkeKeyPair;
use libcrux_traits::kem::arrayref::Kem;
use rand_core::{CryptoRng, RngCore};

// temp: use proper type
// This is a DH-AKEM key
#[derive(Debug, Clone)]
pub struct MessageEncPrivateKey(DHPrivateKey);

#[derive(Debug, Clone)]
pub struct MessageEncPublicKey(DHPublicKey);

impl MessageEncPublicKey {
    pub fn new(public_key: DHPublicKey) -> Self {
        Self(public_key)
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    pub fn from_bytes(bytes: [u8; PK_LEN]) -> Self {
        Self(DHPublicKey::from_bytes(bytes))
    }
}

impl MessageEncPrivateKey {
    pub fn new(private_key: DHPrivateKey) -> Self {
        Self(private_key)
    }

    pub fn into_bytes(self) -> [u8; SK_LEN] {
        self.0.into_bytes()
    }

    pub fn from_bytes(bytes: [u8; SK_LEN]) -> Self {
        Self(DHPrivateKey::from_bytes(bytes))
    }
}


#[derive(Debug, Clone)]
pub struct MessagePQPSKEncapsKey();
pub struct MessagePQPSKDecapsKey();


#[derive(Debug, Clone)]
pub struct MetadataEncapsKey();
pub struct MetadataDecapsKey();


/// TODO: use proper type
/// These are plain DH keys (not DH-AKEM)
pub type FetchPublicKey = DHPublicKey;
pub type  FetchPrivateKey = DHPrivateKey;

/// TODO: will this still exist? Long-term DH key for journalists
pub type JournalistDHPublicKey = DHPublicKey;
pub type JournalistDHPrivateKey = DHPrivateKey;

/// TODO: these are plain DH keys used to calculate "Clue"
/// (aka Z, X, aka mgdh) and Per-Request Clue aka pmgdh
pub type EphemeralDHPublicKey = DHPublicKey;
pub type EphemeralDHPrivateKey = DHPrivateKey;

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

/// Generate new PQ-KEM (ML-KEM768) encaps/decaps pair.
/// Not our prod method! Expose randomness for benchmark purposes
pub fn generate_pqkem_keypair<R: RngCore + CryptoRng>(
    mut rng: R,
) -> Result<(MessagePQPSKDecapsKey, MessagePQPSKEncapsKey), Error> {
    unimplemented!()
    // TODO!!
}

/// Generate new PQ-KEM (ML-KEM768) encaps/decaps pair.
/// Not our prod method! Expose randomness for benchmark purposes
pub fn generate_xwing_keypair<R: RngCore + CryptoRng>(
    mut rng: R,
) -> Result<(MetadataDecapsKey, MetadataEncapsKey), Error> {
    unimplemented!()

    // TODO !!
}
