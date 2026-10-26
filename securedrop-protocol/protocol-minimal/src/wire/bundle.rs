use alloc::string::String;
use alloc::vec::Vec;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use crate::keys::bundle::{KeyBundlePublic, LongtermKeyBundle};
use crate::message::MessagePublicKey;
use crate::primitives::ristretto255::DHPublicKey;
use crate::sign::{JournalistEphemeralKey, JournalistLongTermKey, Signature};

/// The public half of an ephemeral key bundle together with the journalist's
/// self-signature over it.
pub type SignedKeyBundlePublic = (KeyBundlePublic, Signature<JournalistEphemeralKey>);

#[derive(Debug, Clone)]
pub struct SignedLongtermKeyBundle {
    pub bundle: LongtermKeyBundle,
    pub selfsig: Signature<JournalistLongTermKey>,
}

impl SignedLongtermKeyBundle {
    pub fn new(bundle: LongtermKeyBundle, selfsig: Signature<JournalistLongTermKey>) -> Self {
        Self { bundle, selfsig }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let bundle_bytes = self.bundle.as_bytes();
        let sig_bytes = self.selfsig.as_bytes();

        let mut pubkey_bytes = Vec::with_capacity(bundle_bytes.len() + sig_bytes.len());
        pubkey_bytes.extend_from_slice(&bundle_bytes);
        pubkey_bytes.extend_from_slice(&sig_bytes);

        pubkey_bytes
    }

    pub fn bundle_bytes(&self) -> [u8; LongtermKeyBundle::LEN] {
        self.bundle.as_bytes()
    }

    pub fn apke(&self) -> &MessagePublicKey {
        &self.bundle.apke
    }

    pub fn fetch_pk(&self) -> &DHPublicKey {
        &self.bundle.fetch_pk
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl Serialize for SignedLongtermKeyBundle {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.as_bytes()))
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl<'de> Deserialize<'de> for SignedLongtermKeyBundle {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        type Sig = Signature<JournalistLongTermKey>;
        let s = String::deserialize(de)?;
        let mut bytes = [0u8; LongtermKeyBundle::LEN + Sig::LEN];
        hex::decode_to_slice(s.trim(), &mut bytes).map_err(D::Error::custom)?;

        let offset = MessagePublicKey::LEN;
        let apke = MessagePublicKey::from_bytes(&bytes[..offset]).map_err(D::Error::custom)?;
        let mut fetch_key_bytes = [0u8; DHPublicKey::LEN];
        fetch_key_bytes.copy_from_slice(&bytes[offset..offset + DHPublicKey::LEN]);
        let fetch = DHPublicKey::decode(fetch_key_bytes).map_err(D::Error::custom)?;
        let mut sig_bytes = [0u8; Sig::LEN];
        sig_bytes.copy_from_slice(&bytes[offset + DHPublicKey::LEN..]);
        Ok(Self {
            bundle: LongtermKeyBundle::new(apke, fetch),
            selfsig: Sig::from_bytes(sig_bytes),
        })
    }
}
