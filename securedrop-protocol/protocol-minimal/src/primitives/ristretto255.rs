//! Diffie-Hellman over ristretto255 [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496)

use crate::primitives::provider;

pub const DH_PUBLIC_KEY_LEN: usize = provider::ristretto255::PK_LEN;
pub(crate) const DH_PRIVATE_KEY_LEN: usize = provider::ristretto255::SK_LEN;
pub(crate) const DH_SHARED_SECRET_LEN: usize = provider::ristretto255::LEN_DH_SHARE;

/// Uniform bytes required to derive a scalar per [RFC 9496] section 4.4.
pub const DH_SEED_LEN: usize = provider::ristretto255::SEED_LEN;

/// A compressed ristretto255 group element.
#[derive(Debug, Clone, Copy)]
pub struct DHPublicKey([u8; DH_PUBLIC_KEY_LEN]);

/// A ristretto255 scalar in $\mathbb{Z}_\ell$ canonically encoded.
#[derive(Debug, Clone)]
pub struct DHPrivateKey([u8; DH_PRIVATE_KEY_LEN]);
