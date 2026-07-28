//! Diffie-Hellman over ristretto255 [RFC 9496]

use crate::primitives::provider;

pub const DH_PUBLIC_KEY_LEN: usize = provider::ristretto255::PK_LEN;
pub(crate) const DH_PRIVATE_KEY_LEN: usize = provider::ristretto255::SK_LEN;
pub(crate) const DH_SHARED_SECRET_LEN: usize = provider::ristretto255::LEN_DH_SHARE;
