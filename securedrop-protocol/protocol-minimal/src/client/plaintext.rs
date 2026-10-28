use crate::primitives::ristretto255::DHPublicKey;
use crate::primitives::xwing::XWingPublicKey;
use alloc::vec::Vec;
use anyhow::Error;

#[derive(Debug, Clone)]
/// Toy pt structure
pub struct Plaintext {
    /// Fetching key: $pk_S^{fetch}$ in the spec
    pub sender_fetch_key: DHPublicKey,
    /// Metadata key: $pk_S^{PKE}$ in the spec
    pub sender_reply_pubkey_hybrid: [u8; XWingPublicKey::LEN],
    /// Message
    pub msg: Vec<u8>,
}

impl Plaintext {
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.sender_fetch_key.into_bytes());
        buf.extend_from_slice(&self.sender_reply_pubkey_hybrid);
        buf.extend_from_slice(&self.msg);

        buf
    }

    pub fn len(&self) -> usize {
        DHPublicKey::LEN + XWingPublicKey::LEN + self.msg.len()
    }

    // Toy parsing only
    pub fn from_bytes(pt_bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;

        let mut fetch_key_bytes = [0u8; DHPublicKey::LEN];
        fetch_key_bytes.copy_from_slice(&pt_bytes[offset..offset + DHPublicKey::LEN]);

        let sender_fetch_key = DHPublicKey::decode(fetch_key_bytes)?;
        offset += DHPublicKey::LEN;

        let mut sender_reply_pubkey_hybrid = [0u8; XWingPublicKey::LEN];
        sender_reply_pubkey_hybrid.copy_from_slice(&pt_bytes[offset..offset + XWingPublicKey::LEN]);
        offset += XWingPublicKey::LEN;

        let msg = pt_bytes[offset..].to_vec();

        Ok(Plaintext {
            sender_fetch_key,
            sender_reply_pubkey_hybrid,
            msg,
        })
    }
}
