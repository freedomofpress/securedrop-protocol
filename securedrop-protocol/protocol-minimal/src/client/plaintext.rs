use crate::metadata::MetadataPublicKey;
use crate::primitives::ristretto255::DHPublicKey;
use alloc::vec::Vec;
use anyhow::Error;

#[derive(Debug, Clone)]
/// Toy pt structure
pub struct Plaintext {
    /// Fetching key: $pk_S^{fetch}$ in the spec
    pub sender_fetch_key: DHPublicKey,
    /// Metadata key: $pk_S^{PKE}$ in the spec
    pub sender_reply_pubkey_hybrid: MetadataPublicKey,
    /// Message
    pub msg: Vec<u8>,
}

impl Plaintext {
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.sender_fetch_key.into_bytes());
        buf.extend_from_slice(self.sender_reply_pubkey_hybrid.as_bytes());
        buf.extend_from_slice(&self.msg);

        buf
    }

    pub fn len(&self) -> usize {
        DHPublicKey::LEN + MetadataPublicKey::LEN + self.msg.len()
    }

    // Toy parsing only
    pub fn from_bytes(pt_bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;

        let mut fetch_key_bytes = [0u8; DHPublicKey::LEN];
        fetch_key_bytes.copy_from_slice(&pt_bytes[offset..offset + DHPublicKey::LEN]);

        let sender_fetch_key = DHPublicKey::decode(fetch_key_bytes)?;
        offset += DHPublicKey::LEN;

        let sender_reply_pubkey_hybrid =
            MetadataPublicKey::from_bytes(&pt_bytes[offset..offset + MetadataPublicKey::LEN])?;
        offset += MetadataPublicKey::LEN;

        let msg = pt_bytes[offset..].to_vec();

        Ok(Plaintext {
            sender_fetch_key,
            sender_reply_pubkey_hybrid,
            msg,
        })
    }
}
