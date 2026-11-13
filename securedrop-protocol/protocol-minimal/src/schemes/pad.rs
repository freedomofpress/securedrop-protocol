use alloc::vec;
use alloc::vec::Vec;
use anyhow::Error;

/// Fixed-length padded message length.
///
/// Note: I made this up. We should pick something based on actual reasons.
pub const PADDED_MESSAGE_LEN: usize = 100000;

pub trait Encodable {
    // Serialize the object into bytes.
    fn encode(&self) -> Vec<u8>;

    // Deserialize from bytes into the object. Returns an error if the bytes are invalid.
    fn decode(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait PaddingScheme {
    const LEN: usize;
}

pub struct Padded<T, S> {
    bytes: Vec<u8>,
    _marker: core::marker::PhantomData<(T, S)>,
}

impl<T: Encodable, S: PaddingScheme> Padded<T, S> {
    // Max content length, excluding the prepended length field.
    pub const MAX_MESSAGE_LEN: usize = S::LEN - 4;

    // Pads an Encodable value T to a fixed length defined by the PaddingScheme, with format (u32(len) || value || 00...). Returns an error if the value is too large to fit in the padded length.
    pub fn pad(value: &T) -> Result<Self, Error> {
        let mut bytes = value.encode();
        if bytes.len() > Self::MAX_MESSAGE_LEN {
            return Err(anyhow::anyhow!("Value too large to pad"));
        }
        let mut padded_bytes = Vec::with_capacity(S::LEN);
        // Prepend the length of the content as a 4-byte little-endian integer.
        let len_bytes = (bytes.len() as u32).to_le_bytes();

        padded_bytes.extend_from_slice(&len_bytes);
        padded_bytes.extend_from_slice(&bytes);
        padded_bytes.resize(S::LEN, 0);
        Ok(Self {
            bytes: padded_bytes,
            _marker: core::marker::PhantomData,
        })
    }

    // Unpads the Padded object and returns the original Encodable value T. Returns an error if the padding is invalid or if the content length exceeds the maximum allowed length.
    pub fn unpad(&self) -> Result<T, Error> {
        // Read the first 4 bytes as the length of the content.
        let len_bytes: [u8; 4] = self.bytes[0..4].try_into().unwrap();
        let content_len = u32::from_le_bytes(len_bytes) as usize;
        if content_len > Self::MAX_MESSAGE_LEN {
            return Err(anyhow::anyhow!("Invalid content length"));
        }
        // Check that the padding is all zeros after the content.
        for &byte in &self.bytes[4 + content_len..] {
            if byte != 0 {
                return Err(anyhow::anyhow!("Invalid zero padding"));
            }
        }

        // Extract the content bytes.
        let content_bytes = &self.bytes[4..4 + content_len];
        T::decode(content_bytes)
    }

    // Returns the padded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    // Create a Padded object from bytes. Returns an error if the length is not equal to the expected padded length.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() != S::LEN {
            return Err(anyhow::anyhow!("Invalid padded length"));
        }
        Ok(Self {
            bytes,
            _marker: core::marker::PhantomData,
        })
    }
}

/// Pad a message to a fixed length.
///
/// # Panics
///
/// Panics if `message` is longer than `PADDED_MESSAGE_LEN`. The verification
/// precondition (`requires`) rules this out, so the panic is provably
/// unreachable and the length subtraction is safe.
#[cfg_attr(hax, hax_lib::requires(message.len() <= PADDED_MESSAGE_LEN))]
pub fn pad_message(message: &[u8]) -> Vec<u8> {
    if message.len() > PADDED_MESSAGE_LEN {
        panic!("Message too long for padding");
    }

    let mut padded = Vec::with_capacity(PADDED_MESSAGE_LEN);
    padded.extend_from_slice(message);

    // Append zeros to reach the fixed length.
    let padding = alloc::vec![0u8; PADDED_MESSAGE_LEN - message.len()];
    padded.extend_from_slice(&padding);

    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestScheme;
    impl PaddingScheme for TestScheme {
        const LEN: usize = 32;
    }

    // Test object with 4 bytes data and rest of the bytes as data1.
    struct TestObject {
        value: u32,
        data: Vec<u8>,
    }
    impl Encodable for TestObject {
        fn encode(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.extend_from_slice(&self.value.to_le_bytes());
            buf.extend_from_slice(&self.data);
            buf
        }
        fn decode(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.len() < 4 {
                return Err(anyhow::anyhow!("Not enough bytes to decode TestObject"));
            }
            let value = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let data = bytes[4..].to_vec();
            Ok(TestObject {
                value: value,
                data: data,
            })
        }
    }

    type TestPlaintext = Padded<TestObject, TestScheme>;

    #[test]
    fn test_padded_object() {
        let obj = TestObject {
            value: 22,
            data: vec![5, 6, 7, 8],
        };
        let padded = TestPlaintext::pad(&obj).unwrap();
        assert_eq!(padded.as_bytes().len(), TestScheme::LEN);

        let unpadded: TestObject = padded.unpad().unwrap();
        assert_eq!(unpadded.data, obj.data);
        assert_eq!(unpadded.value, obj.value);
    }

    // Test object too large to pad
    // Test error on unpad - length corrupt
    // Test error on unpad - too large length
    // Test error on unpad - too small length
    // Test error on unpad - corrupt padding
    // Test nul bytes in content
    // Test from_bytes failure on wrong length
}
