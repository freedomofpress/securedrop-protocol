//! Diffie-Hellman over ristretto255 [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496)
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

use crate::primitives::provider;

pub const DH_PUBLIC_KEY_LEN: usize = provider::ristretto255::PK_LEN;
pub(crate) const DH_PRIVATE_KEY_LEN: usize = provider::ristretto255::SK_LEN;
pub(crate) const DH_SHARED_SECRET_LEN: usize = provider::ristretto255::LEN_DH_SHARE;

/// Uniform bytes required to derive a scalar per [RFC 9496] section 4.4.
pub const DH_SEED_LEN: usize = provider::ristretto255::SEED_LEN;

/// A compressed ristretto255 group element.
///
/// # Security
///
/// This can be instantiated only by going through point decompression
/// to ensure it is a valid ristretto255 group element.
///
/// TODO(jen): Internal `CompressedRistretto` and `RistrettoPoint`?
#[derive(Debug, Clone, Copy)]
pub struct DHPublicKey([u8; DH_PUBLIC_KEY_LEN]);

/// A ristretto255 scalar in $\mathbb{Z}_\ell$ canonically encoded.
///
/// TODO(jen): Internal `Scalar` - not doing this at this moment
/// because the providers module interface is all byte based
#[derive(Debug, Clone)]
pub struct DHPrivateKey([u8; DH_PRIVATE_KEY_LEN]);

/// A DH agreement output (a compressed ristretto255 group element).
#[derive(Debug, Clone)]
pub struct DHSharedSecret([u8; DH_SHARED_SECRET_LEN]);

impl DHPublicKey {
    /// Decode a group element from its 32 byte encoding, validating that it is a
    /// real ristretto255 element.
    ///
    /// This must be used for any untrusted bytes (wire or storage) such that an
    /// invalid element cannot be instantiated.
    pub fn decode(bytes: [u8; DH_PUBLIC_KEY_LEN]) -> Result<Self, Error> {
        let canonical = provider::ristretto255::decode(&bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid ristretto255 point encoding"))?;
        Ok(Self(canonical))
    }

    /// This can only be used for trusted bytes.
    ///
    /// TODO(Jen): remove this
    pub(crate) fn from_bytes(bytes: [u8; DH_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The canonical 32-byte encoding of this element.
    pub fn into_bytes(self) -> [u8; DH_PUBLIC_KEY_LEN] {
        self.0
    }
}

impl DHPrivateKey {
    /// Decode a scalar from bytes, validating it is a canonical element of
    /// $\mathbb{Z}_\ell$.
    pub fn decode(bytes: [u8; DH_PRIVATE_KEY_LEN]) -> Result<Self, Error> {
        let canonical = provider::ristretto255::scalar_decode(&bytes)
            .ok_or_else(|| anyhow::anyhow!("non-canonical ristretto255 scalar"))?;
        Ok(Self(canonical))
    }

    /// Derive the public key $[sk] B$.
    pub fn public_key(&self) -> DHPublicKey {
        let pk = provider::ristretto255::secret_to_public(&self.0)
            .expect("DHPrivateKey holds a canonical scalar");
        DHPublicKey(pk)
    }

    pub fn as_bytes(&self) -> &[u8; DH_PRIVATE_KEY_LEN] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; DH_PRIVATE_KEY_LEN] {
        self.0
    }
}

impl DHSharedSecret {
    pub fn into_bytes(self) -> [u8; DH_SHARED_SECRET_LEN] {
        self.0
    }
}

/// Derive a DH keypair from a caller-supplied uniform seed.
///
/// Used for keys that must be reproducible from a key hierarchy (the source's
/// $sk_S^{fetch}$), and for deterministic tests.
pub(crate) fn deterministic_dh_keygen(
    randomness: [u8; DH_SEED_LEN],
) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    let secret_key = provider::ristretto255::scalar_from_wide(&randomness);
    let public_key = provider::ristretto255::secret_to_public(&secret_key)
        .ok_or_else(|| anyhow::anyhow!("ristretto255 key generation failed"))?;

    Ok((DHPrivateKey(secret_key), DHPublicKey(public_key)))
}

/// Generate a new ristretto255 DH keypair
pub fn generate_dh_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    let mut randomness = [0u8; DH_SEED_LEN];
    provider::rng::fill_bytes(rng, &mut randomness);

    deterministic_dh_keygen(randomness)
}

/// Sample a uniformly random group element.
pub fn random_dh_public_key<R: RngCore + CryptoRng>(rng: &mut R) -> DHPublicKey {
    let mut randomness = [0u8; DH_SEED_LEN];
    provider::rng::fill_bytes(rng, &mut randomness);

    DHPublicKey(provider::ristretto255::from_uniform_bytes(&randomness))
}

/// Sample a scalar $x \gets^{\$} \mathbb{F}_\ell$.
pub fn generate_random_scalar<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<[u8; DH_PRIVATE_KEY_LEN], Error> {
    let mut randomness = [0u8; DH_SEED_LEN];
    provider::rng::fill_bytes(rng, &mut randomness);

    Ok(provider::ristretto255::scalar_from_wide(&randomness))
}

/// Compute DH agreement.
pub fn dh_shared_secret(
    public_key: &DHPublicKey,
    scalar: [u8; DH_PRIVATE_KEY_LEN],
) -> Result<DHSharedSecret, Error> {
    let shared = provider::ristretto255::dh(&public_key.0, &scalar)
        .ok_or_else(|| anyhow::anyhow!("ristretto255 DH failed"))?;
    Ok(DHSharedSecret(shared))
}

#[cfg_attr(hax, hax_lib::exclude)]
impl serde::Serialize for DHPublicKey {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.0))
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
