//! Diffie-Hellman over ristretto255 [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496)
use anyhow::Error;

use crate::primitives::provider;

pub const DH_PUBLIC_KEY_LEN: usize = provider::ristretto255::PK_LEN;
pub(crate) const DH_PRIVATE_KEY_LEN: usize = provider::ristretto255::SK_LEN;
pub(crate) const DH_SHARED_SECRET_LEN: usize = provider::ristretto255::LEN_DH_SHARE;

/// Uniform bytes required to derive a scalar per [RFC 9496] section 4.4.
pub const DH_SEED_LEN: usize = provider::ristretto255::SEED_LEN;

/// A compressed ristretto255 group element.
///
/// TODO(jen): Internal `CompressedRistretto``
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

/// Derive a DH keypair from a caller-supplied uniform seed.
///
/// Used for keys that must be reproducible from a key hierarchy (the source's
/// $sk_S^{fetch}$), and for deterministic tests.
fn deterministic_dh_keygen(
    randomness: [u8; DH_SEED_LEN],
) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    let secret_key = provider::ristretto255::scalar_from_wide(&randomness);
    let public_key = provider::ristretto255::secret_to_public(&secret_key)
        .ok_or_else(|| anyhow::anyhow!("ristretto255 key generation failed"))?;

    Ok((DHPrivateKey(secret_key), DHPublicKey(public_key)))
}
