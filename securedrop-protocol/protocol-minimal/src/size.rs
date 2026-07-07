use alloc::vec::Vec;

use crate::metadata::MetadataCiphertext;
use crate::primitives::dh_akem::DH_AKEM_ENCAPS_SECRET_LEN;
use crate::primitives::mlkem::LEN_MLKEM_SHAREDSECRET_ENCAPS;
use crate::primitives::x25519::DH_PUBLIC_KEY_LEN;
use crate::primitives::x25519::DH_SHARED_SECRET_LEN;
use core::marker::PhantomData;

/// Total size in bytes of encrypted envelope.
/// IMPORTANT: DEFINE THIS SIZE ONLY and let other sizes be calculated from here.
/// This should always be equal to Envelope::SIZE.
/// Message length is adjusted by changing this number.
/// TODO: this is an arbitrary value!
/// Also TODO: can expose this somewhere more obvious with better developer documentation (eg lib.rs)
const MAX_ENCRYPTED_ENVELOPE_SIZE: usize = 100000;

// Remaining size info
// All other components are calculated from above or are based on size constraints.
pub(crate) const AEAD_TAG_LEN: usize = 16;
pub(crate) const CLUE_SIZE: usize = DH_SHARED_SECRET_LEN + DH_PUBLIC_KEY_LEN;

// Remaining APKE components
// CIPHERTEXT_WIRE_SIZE is the size that a padded message should encrypt to
const CIPHERTEXT_WIRE_SIZE: usize = MAX_ENCRYPTED_ENVELOPE_SIZE
    - CLUE_SIZE
    - MetadataCiphertext::SIZE
    - DH_AKEM_ENCAPS_SECRET_LEN
    - LEN_MLKEM_SHAREDSECRET_ENCAPS;

// PLAINTEXT_WIRE_MAX_PADDED_SIZE is the size that pad(message) should pad to, aka max message length
// This size is exposed to pad.rs
// todo deprecate pad.rs
pub(crate) const PLAINTEXT_WIRE_MAX_PADDED_SIZE: usize = CIPHERTEXT_WIRE_SIZE - AEAD_TAG_LEN;

// Below for developer info only
// What amount of characters can a message occupy?
// Includes a User's message string plus any other serialized application-level data (such as app-level message id, date/timestamp, etc)
// const PLAINTEXT_MESSAGE_USABLE_MAX_SIZE: usize = PLAINTEXT_WIRE_MAX_PADDED_SIZE - XWING_PUBLIC_KEY_LEN - DH_PUBLIC_KEY_LEN;
// sanity: OVERHEAD == MAX_ENCRYPTED_ENVELOPE_SIZE - MetadataCiphertext::SIZE - CLUE_SIZE - XWING_PUBLIC_KEY_LEN - DH_PUBLIC_KEY_LEN - DH_AKEM_ENCAPS_SECRET_LEN - LEN_MLKEM_SHAREDSECRET_ENCAPS;
// const OVERHEAD: usize = MAX_ENCRYPTED_ENVELOPE_SIZE - PLAINTEXT_MESSAGE_USABLE_MAX_SIZE;

#[derive(Debug, Clone, PartialEq)]
pub struct FixedSizeBytes<Tag, const N: usize> {
    bytes: Vec<u8>,
    _tag: PhantomData<Tag>,
}

impl<Tag, const N: usize> FixedSizeBytes<Tag, N> {
    pub const SIZE: usize = N;

    pub fn new(bytes: Vec<u8>) -> Self {
        if bytes.len() != N {
            panic!("Wrong size (want {}, got {})", N, bytes.len())
        }

        Self {
            bytes,
            _tag: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    //todo error type
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, anyhow::Error> {
        if bytes.len() != N {
            return Err(anyhow::anyhow!(
                "Wrong length bytes (want {}, got {})",
                N,
                bytes.len()
            ));
        }

        Ok(Self {
            bytes,
            _tag: PhantomData,
        })
    }
}

// Markers, so that something besides length distinguishes the types.
#[derive(Debug, Clone, PartialEq)]
pub enum PlaintextTag {}

#[derive(Debug, Clone, PartialEq)]
pub enum CiphertextTag {}

// Fixed-size types (heap backed due to size)
pub type PlaintextWire = FixedSizeBytes<PlaintextTag, PLAINTEXT_WIRE_MAX_PADDED_SIZE>;

pub type CiphertextWire = FixedSizeBytes<CiphertextTag, CIPHERTEXT_WIRE_SIZE>;
