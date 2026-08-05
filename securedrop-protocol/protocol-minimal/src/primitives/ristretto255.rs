//! Diffie-Hellman over ristretto255 [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496)
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

use crate::primitives::provider;
use crate::primitives::provider::ristretto255::{Point, Scalar};

pub const DH_PUBLIC_KEY_LEN: usize = provider::ristretto255::PK_LEN;
pub(crate) const DH_PRIVATE_KEY_LEN: usize = provider::ristretto255::SK_LEN;

/// Uniform bytes required to derive a scalar per [RFC 9496] section 4.4.
pub const DH_SEED_LEN: usize = provider::ristretto255::SEED_LEN;

/// A ristretto255 group element.
///
/// # Security
///
/// This can be instantiated only by decoding, by the element derivation
/// function, or by a group operation, so it is always a valid ristretto255
/// element. The element is held decompressed, so repeated operations on the
/// same key do not repeat point decompression.
#[derive(Debug, Clone, Copy)]
pub struct DHPublicKey(Point);

/// A ristretto255 scalar in $\mathbb{Z}_\ell$.
///
/// This can be instantiated only by validating decode or by wide reduction, so
/// it is always canonical.
#[derive(Debug, Clone)]
pub struct DHPrivateKey(Scalar);

impl DHPublicKey {
    /// Decode a group element from its 32 byte encoding, validating that it is a
    /// real ristretto255 element.
    ///
    /// This must be used for any untrusted bytes (wire or storage) such that an
    /// invalid element cannot be instantiated.
    pub fn decode(bytes: [u8; DH_PUBLIC_KEY_LEN]) -> Result<Self, Error> {
        provider::ristretto255::decode(&bytes)
            .map(Self)
            .ok_or_else(|| anyhow::anyhow!("invalid ristretto255 point encoding"))
    }

    /// The canonical 32-byte encoding of this element.
    pub fn into_bytes(self) -> [u8; DH_PUBLIC_KEY_LEN] {
        provider::ristretto255::encode(&self.0)
    }
}

impl DHPrivateKey {
    /// Decode a scalar from bytes, validating it is a canonical element of
    /// $\mathbb{Z}_\ell$.
    pub fn decode(bytes: [u8; DH_PRIVATE_KEY_LEN]) -> Result<Self, Error> {
        provider::ristretto255::scalar_decode(&bytes)
            .map(Self)
            .ok_or_else(|| anyhow::anyhow!("non-canonical ristretto255 scalar"))
    }

    /// Derive the public key $[sk] B$.
    pub fn public_key(&self) -> DHPublicKey {
        DHPublicKey(provider::ristretto255::secret_to_public(&self.0))
    }

    /// The canonical encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; DH_PRIVATE_KEY_LEN] {
        provider::ristretto255::scalar_encode(&self.0)
    }
}

/// Derive a DH keypair from a caller-supplied uniform seed.
///
/// Used for keys that must be reproducible from a key hierarchy (the source's
/// $sk_S^{fetch}$), and for deterministic tests.
pub(crate) fn deterministic_dh_keygen(
    randomness: [u8; DH_SEED_LEN],
) -> (DHPrivateKey, DHPublicKey) {
    let secret_key = DHPrivateKey(provider::ristretto255::scalar_from_wide(&randomness));
    let public_key = secret_key.public_key();

    (secret_key, public_key)
}

/// Generate a new ristretto255 DH keypair
pub fn generate_dh_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (DHPrivateKey, DHPublicKey) {
    let mut randomness = [0u8; DH_SEED_LEN];
    provider::rng::fill_bytes(rng, &mut randomness);

    deterministic_dh_keygen(randomness)
}

/// The seed to [`placeholder_public_key`].
const PLACEHOLDER_SEED: &[u8] = b"securedrop-protocol-placeholder-v1";

/// A fixed group element used as a placeholder value.
pub fn placeholder_public_key() -> DHPublicKey {
    let seed = provider::sha2::sha512(PLACEHOLDER_SEED);

    DHPublicKey(provider::ristretto255::from_uniform_bytes(&seed))
}

/// Sample a uniformly random group element.
pub fn random_dh_public_key<R: RngCore + CryptoRng>(rng: &mut R) -> DHPublicKey {
    let mut randomness = [0u8; DH_SEED_LEN];
    provider::rng::fill_bytes(rng, &mut randomness);

    DHPublicKey(provider::ristretto255::from_uniform_bytes(&randomness))
}

/// Sample a scalar $x \gets^{\$} \mathbb{F}_\ell$.
pub fn generate_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> DHPrivateKey {
    let mut randomness = [0u8; DH_SEED_LEN];
    provider::rng::fill_bytes(rng, &mut randomness);

    DHPrivateKey(provider::ristretto255::scalar_from_wide(&randomness))
}

/// Compute DH agreement.
pub fn dh_shared_secret(public_key: &DHPublicKey, scalar: &DHPrivateKey) -> DHPublicKey {
    DHPublicKey(provider::ristretto255::dh(&public_key.0, &scalar.0))
}

#[cfg_attr(hax, hax_lib::exclude)]
impl serde::Serialize for DHPublicKey {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.into_bytes()))
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl<'de> serde::Deserialize<'de> for DHPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = alloc::string::String::deserialize(de)?;
        let mut bytes = [0u8; DH_PUBLIC_KEY_LEN];
        hex::decode_to_slice(s.trim(), &mut bytes).map_err(D::Error::custom)?;
        // We validate at the wire boundary and reject a malformed encoding here.
        Self::decode(bytes).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn get_rng() -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS random source failed");
        ChaCha20Rng::from_seed(seed)
    }

    #[test]
    fn test_deterministic_dh_keygen() {
        proptest!(|(randomness in proptest::collection::vec(any::<u8>(), DH_SEED_LEN))| {
            let seed: [u8; DH_SEED_LEN] = randomness.try_into().unwrap();
            let (sk, pk) = deterministic_dh_keygen(seed);

            let (sk2, pk2) = deterministic_dh_keygen(seed);
            prop_assert_eq!(sk.to_bytes(), sk2.to_bytes());
            prop_assert_eq!(pk.into_bytes(), pk2.into_bytes());
            prop_assert_eq!(pk.into_bytes(), sk.public_key().into_bytes());
        });
    }

    #[test]
    fn test_dh_shared_secret() {
        let mut rng = get_rng();

        let (sk1, pk1) = generate_dh_keypair(&mut rng);

        let (sk2, pk2) = generate_dh_keypair(&mut rng);

        let ss1 = dh_shared_secret(&pk1, &sk2);
        let ss2 = dh_shared_secret(&pk2, &sk1);

        assert_eq!(ss1.into_bytes(), ss2.into_bytes());
        assert_ne!(ss1.into_bytes(), [0u8; DH_PUBLIC_KEY_LEN])
    }

    #[test]
    fn test_three_party_dh() {
        let mut rng = get_rng();

        let (sk_r, pk_r) = generate_dh_keypair(&mut rng);
        let (x, big_x) = generate_dh_keypair(&mut rng);
        let y = generate_random_scalar(&mut rng);

        let z = dh_shared_secret(&pk_r, &x);
        let server = dh_shared_secret(&z, &y);

        let pmgdh = dh_shared_secret(&big_x, &y);
        let recipient = dh_shared_secret(&pmgdh, &sk_r);

        assert_eq!(server.into_bytes(), recipient.into_bytes());
    }
}
