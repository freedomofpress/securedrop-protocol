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
        if pt_bytes.len() < DHPublicKey::LEN + MetadataPublicKey::LEN {
            return Err(anyhow::anyhow!("plaintext is shorter than its key header"));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ristretto255::random_dh_public_key;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_plaintext_rejects_truncated_header() {
        let header_len = DHPublicKey::LEN + MetadataPublicKey::LEN;
        let bytes = alloc::vec![0u8; header_len];

        for len in 0..header_len {
            assert!(
                Plaintext::from_bytes(&bytes[..len]).is_err(),
                "accepted a truncated plaintext header of {len} bytes"
            );
        }
    }

    #[test]
    fn test_plaintext_preserves_complete_header_and_message() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let fetch_key_bytes = random_dh_public_key(&mut rng).into_bytes();
        let reply_key_bytes = [0x42u8; MetadataPublicKey::LEN];

        for message in [b"".as_slice(), b"\x00\xffbinary message".as_slice()] {
            // Assemble the wire bytes independently of Plaintext::to_bytes.
            let mut bytes = fetch_key_bytes.to_vec();
            bytes.extend_from_slice(&reply_key_bytes);
            bytes.extend_from_slice(message);

            let restored = Plaintext::from_bytes(&bytes).expect("complete plaintext");
            assert_eq!(restored.sender_fetch_key.into_bytes(), fetch_key_bytes);
            assert_eq!(
                restored.sender_reply_pubkey_hybrid.as_bytes(),
                reply_key_bytes
            );
            assert_eq!(restored.msg, message);
        }
    }

    #[test]
    fn test_plaintext_rejects_invalid_fetch_key() {
        let mut bytes = alloc::vec![0u8; DHPublicKey::LEN + MetadataPublicKey::LEN];
        bytes[..DHPublicKey::LEN].fill(0xff);

        assert!(Plaintext::from_bytes(&bytes).is_err());
    }
}
