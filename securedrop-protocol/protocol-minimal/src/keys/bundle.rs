use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::message::{MessageKeyPair, MessagePublicKey};
use crate::metadata::{MetadataKeyPair, MetadataPublicKey};
use crate::primitives::ristretto255::DHPublicKey;
use crate::sign::{JournalistEphemeralKey, Signature};

/// The public keys that make up one ephemeral key bundle
#[derive(Debug, Clone)]
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct KeyBundlePublic {
    /// SD-APKE ephemeral key `pk_{J,i}^{APKE_E} = (pk1, pk2)`.
    pub apke_pk: MessagePublicKey,
    /// SD-PKE ephemeral key, used for metadata protection.
    pub metadata_pk: MetadataPublicKey,
}

impl KeyBundlePublic {
    /// Serialize the bundle public keys in canonical byte order for signing.
    ///
    /// Layout: `pk_{J,i}^{APKE_E}(DHKEM) || pk_{J,i}^{APKE_E}(ML-KEM) || pk_{J,i}^{PKE_E}(X-Wing)`
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.apke_pk.as_bytes());
        out.extend_from_slice(&self.metadata_pk.as_bytes());
        out
    }
}

pub(crate) struct MessageKeyBundle {
    pub(crate) apke: MessageKeyPair,
    pub(crate) metadata_kp: MetadataKeyPair,
}

impl MessageKeyBundle {
    pub fn new(apke: MessageKeyPair, metadata_kp: MetadataKeyPair) -> Self {
        Self { apke, metadata_kp }
    }

    pub(crate) fn public(&self) -> KeyBundlePublic {
        KeyBundlePublic {
            apke_pk: self.apke.public_key().clone(),
            metadata_pk: self.metadata_kp.public_key().clone(),
        }
    }
}

pub(crate) struct SignedMessageKeyBundle {
    pub(crate) bundle: MessageKeyBundle,
    pub(crate) selfsig: Signature<JournalistEphemeralKey>,
}

#[derive(Debug, Clone)]
pub(crate) struct LongtermKeyBundle {
    pub(crate) apke: MessagePublicKey,
    pub(crate) fetch_pk: DHPublicKey,
}

impl LongtermKeyBundle {
    pub const LEN: usize = MessagePublicKey::LEN + DHPublicKey::LEN;

    pub fn new(apke: MessagePublicKey, fetch_pk: DHPublicKey) -> Self {
        Self { apke, fetch_pk }
    }

    /// Serialize long-term public keys into the canonical byte encoding.
    ///
    /// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
    /// where `pk_J^APKE = pk_J^AKEM (DH-AKEM) || pk_J^PQ (ML-KEM)`
    pub fn as_bytes(&self) -> [u8; Self::LEN] {
        let apke_bytes = self.apke.as_bytes();
        let fetch_bytes = self.fetch_pk.into_bytes();

        let mut pubkey_bytes = [0u8; Self::LEN];
        pubkey_bytes[..apke_bytes.len()].copy_from_slice(&apke_bytes);
        pubkey_bytes[apke_bytes.len()..].copy_from_slice(&fetch_bytes);

        pubkey_bytes
    }
}
