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
    pub const KEY_HEADER_LEN: usize = DHPublicKey::LEN + MetadataPublicKey::LEN;

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.sender_fetch_key.into_bytes());
        buf.extend_from_slice(self.sender_reply_pubkey_hybrid.as_bytes());
        buf.extend_from_slice(&self.msg);

        buf
    }

    pub fn len(&self) -> usize {
        Self::KEY_HEADER_LEN + self.msg.len()
    }

    // Toy parsing only
    fn from_bytes(pt_bytes: &[u8]) -> Result<Self, Error> {
        if pt_bytes.len() < Self::KEY_HEADER_LEN {
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

/// Padded plaintext structure to retrieve encryptable bytes for a Plaintext.
pub struct PaddedPlaintext(Plaintext);

impl PaddedPlaintext {
    /// Length of a padded plaintext message.
    /// TODO(#229): Choose a size based on real requirements
    pub const LEN: usize = 100000;

    const PREFIX_LEN: usize = 4;
    const MAX_CONTENT_LEN: usize = Self::LEN - Self::PREFIX_LEN;

    /// Returns an error if the value is too large to fit in the padded length.
    pub fn new(plaintext: Plaintext) -> Result<Self, Error> {
        if plaintext.len() > Self::MAX_CONTENT_LEN {
            return Err(anyhow::anyhow!("Plaintext too long for padding"));
        }
        Ok(Self(plaintext))
    }

    /// Returns a padded plaintext [u32_le(len) || value || 00...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let content = self.0.to_bytes();
        // Ensure that the length of the content matches Plaintext::len()
        debug_assert_eq!(content.len(), self.0.len());

        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&content);
        out.resize(Self::LEN, 0);
        out
    }

    /// Create a PaddedPlaintext from bytes. Returns an error if the length is not equal to the expected padded length.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<PaddedPlaintext, Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!("Invalid padded length"));
        }
        // Read the first 4 bytes as the length of the content.
        let len_bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > Self::MAX_CONTENT_LEN {
            return Err(anyhow::anyhow!("Content too large to unpad"));
        }

        // Check that the padding is all zeros after the content.
        for &byte in &bytes[4 + len..] {
            if byte != 0 {
                return Err(anyhow::anyhow!("Invalid zero padding"));
            }
        }

        let plaintext = Plaintext::from_bytes(&bytes[4..4 + len])?;
        PaddedPlaintext::new(plaintext)
    }

    pub fn into_inner(self) -> Plaintext {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ristretto255::random_dh_public_key;
    use alloc::vec;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use proptest::prelude::*;

    #[test]
    fn test_plaintext_rejects_truncated_header() {
        let header_len = Plaintext::KEY_HEADER_LEN;
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

    fn make_plaintext(msg: &[u8]) -> Plaintext {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let fetch_key = random_dh_public_key(&mut rng);
        let reply_key = MetadataPublicKey::from_bytes(&[0x42u8; MetadataPublicKey::LEN]).unwrap();

        Plaintext {
            sender_fetch_key: fetch_key,
            sender_reply_pubkey_hybrid: reply_key,
            msg: msg.to_vec(),
        }
    }

    proptest! {
        #[test]
        fn test_padded_plaintext_roundtrip(
            msg in prop::collection::vec(any::<u8>(), 0..=(PaddedPlaintext::MAX_CONTENT_LEN - Plaintext::KEY_HEADER_LEN))
        ) {
        let plaintext = make_plaintext(&msg);
        let padded = PaddedPlaintext::new(plaintext.clone()).unwrap();
        let bytes = padded.to_bytes();
        prop_assert_eq!(bytes.len(), PaddedPlaintext::LEN);
        prop_assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            plaintext.len()
        );

        let restored = PaddedPlaintext::from_bytes(bytes).unwrap().into_inner();
        prop_assert_eq!(restored.msg, msg);
        prop_assert_eq!(
            restored.sender_fetch_key.into_bytes(),
            plaintext.sender_fetch_key.into_bytes()
        );
        prop_assert_eq!(
            restored.sender_reply_pubkey_hybrid.as_bytes(),
            plaintext.sender_reply_pubkey_hybrid.as_bytes()
        );
        }
    }

    #[test]
    fn test_roundtrip_with_nul_message_bytes() {
        let message = "\0\0\0\0\0\0\0\0\0\0".as_bytes().to_vec();

        let plaintext = make_plaintext(&message);
        let padded = PaddedPlaintext::new(plaintext).unwrap();
        let bytes = padded.to_bytes();
        let restored = PaddedPlaintext::from_bytes(bytes).unwrap();
        assert_eq!(restored.into_inner().msg, message);
    }

    #[test]
    fn test_padded_is_fixed_length() {
        for message in [b"".as_slice(), b"\x00\xffbinary message".as_slice()] {
            let plaintext = make_plaintext(message);
            let padded = PaddedPlaintext::new(plaintext).unwrap();
            let bytes = padded.to_bytes();

            assert_eq!(bytes.len(), PaddedPlaintext::LEN);
            let restored = PaddedPlaintext::from_bytes(bytes).unwrap().into_inner();
            assert_eq!(restored.msg, message);
        }
    }

    #[test]
    fn test_unpad_rejects_wrong_length() {
        assert!(PaddedPlaintext::from_bytes(vec![0u8, (PaddedPlaintext::LEN - 1) as u8]).is_err());
    }

    #[test]
    fn test_roundtrip_empty_message() {
        let message = b"".to_vec();
        let plaintext = make_plaintext(&message);
        let padded = PaddedPlaintext::new(plaintext).unwrap();
        let bytes = padded.to_bytes();
        let restored = PaddedPlaintext::from_bytes(bytes).unwrap();
        assert_eq!(restored.into_inner().msg, message);
    }

    #[test]
    fn test_new_rejects_large_message() {
        let max = PaddedPlaintext::LEN - DHPublicKey::LEN - MetadataPublicKey::LEN - 4;

        assert!(PaddedPlaintext::new(make_plaintext(&vec![0u8; max])).is_ok());
        assert!(PaddedPlaintext::new(make_plaintext(&vec![0u8; max + 1])).is_err());
    }

    #[test]
    fn test_unpad_length_too_large() {
        let padded = PaddedPlaintext::new(make_plaintext(b"hello")).unwrap();
        let mut bytes = padded.to_bytes();

        // Corrupt the length prefix to be too large
        let too_large_len = (PaddedPlaintext::LEN - 4 + 1) as u32;
        bytes[0..4].copy_from_slice(&too_large_len.to_le_bytes());

        assert!(PaddedPlaintext::from_bytes(bytes.to_vec()).is_err());
    }

    #[test]
    fn test_unpad_rejects_nonzero_padding() {
        let padded = PaddedPlaintext::new(make_plaintext(b"hello")).unwrap();
        let mut bytes = padded.to_bytes();

        // Corrupt the last padding byte
        *bytes.last_mut().unwrap() = 0x01;

        assert!(PaddedPlaintext::from_bytes(bytes).is_err());
    }

    #[test]
    fn test_unpad_rejects_truncated_plaintext() {
        let padded = PaddedPlaintext::new(make_plaintext(b"hello")).unwrap();
        let mut bytes = padded.to_bytes();

        // Set prefix to 2 so that the content is only two bytes
        bytes[0..4].copy_from_slice(&(2u32).to_le_bytes());

        assert!(PaddedPlaintext::from_bytes(bytes).is_err());
    }
}
