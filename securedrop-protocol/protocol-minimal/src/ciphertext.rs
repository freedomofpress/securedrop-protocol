use crate::message::MessageCiphertext;
use crate::metadata::MetadataCiphertext;
use crate::primitives::provider::constants::LEN_KMID;
use crate::primitives::x25519::{DH_PUBLIC_KEY_LEN, DH_SHARED_SECRET_LEN};
use crate::primitives::xwing::XWING_PUBLIC_KEY_LEN;
use alloc::vec::Vec;
use anyhow::Error;
#[cfg(not(hax))]
use serde::{Deserialize, Serialize};

/// Hex string serde for fixed length byte arrays
#[cfg(not(hax))]
mod hex_array {
    use alloc::string::String;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<const N: usize, S: Serializer>(
        bytes: &[u8; N],
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, const N: usize, D: Deserializer<'de>>(
        de: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(de)?;
        let mut out = [0u8; N];
        hex::decode_to_slice(s.trim(), &mut out).map_err(D::Error::custom)?;
        Ok(out)
    }
}

/// The full submission `(C_S, X, Z)` sent from sender to server in step 6.
///
/// - `C_S = (ct^APKE, ct^PKE)`: the two ciphertexts
/// - `X = g^x`: ephemeral DH public key (hint)
/// - `Z = (pk_R^fetch)^x`: DH share for fetching (hint)
///
/// The server stores `(id, C_S, X, Z)` per message.
#[derive(Debug, Clone)]
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct Envelope {
    /// `ct^APKE`: SD-APKE ciphertext `((c1, cp), c2)` - the encrypted message
    pub(crate) ct_apke: MessageCiphertext,

    /// `ct^PKE`: SD-PKE ciphertext `(c, c')` - the encrypted sender APKE public key
    pub(crate) ct_pke: MetadataCiphertext,

    /// `X = g^x`: ephemeral DH public key for the hint
    #[cfg_attr(not(hax), serde(with = "hex_array"))]
    pub(crate) mgdh_pubkey: [u8; DH_PUBLIC_KEY_LEN],

    /// `Z = (pk_R^fetch)^x`: DH share for fetching
    #[cfg_attr(not(hax), serde(with = "hex_array"))]
    pub(crate) mgdh: [u8; DH_PUBLIC_KEY_LEN],
}

impl Envelope {
    // Used for benchmarks - see wasm_bindgen
    pub fn size_hint(&self) -> usize {
        self.ct_apke.len() + self.ct_pke.len()
    }

    pub fn cmessage_len(&self) -> usize {
        self.ct_apke.len()
    }

    // SD-PKE ciphertext byte length: encapsulation c + AEAD ciphertext c'
    pub fn cmetadata_len(&self) -> usize {
        self.ct_pke.len()
    }
}

#[derive(Debug, Clone)]
/// Toy pt structure - TODO: provide params in correct order
pub struct Plaintext {
    /// Metadata key: $pk_S^{PKE}$ in the spec
    pub sender_reply_pubkey_hybrid: [u8; XWING_PUBLIC_KEY_LEN],
    /// Fetching key: $pk_S^{fetch}$ in the spec
    pub sender_fetch_key: [u8; DH_PUBLIC_KEY_LEN],
    /// Message
    pub msg: Vec<u8>,
}

impl Plaintext {
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        // TODO: Deviates from spec
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.sender_reply_pubkey_hybrid);
        buf.extend_from_slice(&self.sender_fetch_key);
        buf.extend_from_slice(&self.msg);

        buf
    }

    pub fn len(&self) -> usize {
        XWING_PUBLIC_KEY_LEN + DH_PUBLIC_KEY_LEN + self.msg.len()
    }

    // Toy parsing only
    pub fn from_bytes(pt_bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;

        let mut sender_reply_pubkey_hybrid = [0u8; XWING_PUBLIC_KEY_LEN];
        sender_reply_pubkey_hybrid
            .copy_from_slice(&pt_bytes[offset..offset + XWING_PUBLIC_KEY_LEN]);
        offset += XWING_PUBLIC_KEY_LEN;

        let mut sender_fetch_key = [0u8; DH_PUBLIC_KEY_LEN];
        sender_fetch_key.copy_from_slice(&pt_bytes[offset..offset + DH_PUBLIC_KEY_LEN]);
        offset += DH_PUBLIC_KEY_LEN;

        let msg = pt_bytes[offset..].to_vec();

        Ok(Plaintext {
            sender_reply_pubkey_hybrid,
            sender_fetch_key,
            msg,
        })
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct FetchResponse {
    #[cfg_attr(not(hax), serde(with = "hex_array"))]
    pub(crate) enc_id: [u8; LEN_KMID], // aka kmid
    #[cfg_attr(not(hax), serde(with = "hex_array"))]
    pub(crate) pmgdh: [u8; DH_SHARED_SECRET_LEN], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; DH_SHARED_SECRET_LEN]) -> Self {
        Self { enc_id, pmgdh }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::LEN_METADATA_CIPHERTEXT;
    use crate::primitives::dh_akem::DH_AKEM_ENCAPS_SECRET_LEN;
    use crate::primitives::mlkem::LEN_MLKEM_SHAREDSECRET_ENCAPS;
    use crate::primitives::xwing::LEN_XWING_SHAREDSECRET_ENCAPS;
    use proptest::prelude::*;

    fn message_ct(c1: Vec<u8>, cp: Vec<u8>, c2: Vec<u8>) -> MessageCiphertext {
        MessageCiphertext {
            c1: c1.try_into().expect("c1 length"),
            cp,
            c2: c2.try_into().expect("c2 length"),
        }
    }

    proptest! {
        #[test]
        fn test_message_ciphertext_byte_roundtrip(
            c1 in prop::collection::vec(any::<u8>(), DH_AKEM_ENCAPS_SECRET_LEN),
            cp in prop::collection::vec(any::<u8>(), 0..128),
            c2 in prop::collection::vec(any::<u8>(), LEN_MLKEM_SHAREDSECRET_ENCAPS),
        ) {
            let ct = message_ct(c1, cp, c2);
            let restored = MessageCiphertext::from_bytes(&ct.as_bytes()).expect("valid bytes");
            prop_assert_eq!(ct.as_bytes(), restored.as_bytes());
        }

        #[test]
        fn test_metadata_ciphertext_byte_roundtrip(
            c in prop::collection::vec(any::<u8>(), LEN_XWING_SHAREDSECRET_ENCAPS),
            cp in prop::collection::vec(any::<u8>(), LEN_METADATA_CIPHERTEXT)
            .prop_map(|v| v.try_into().unwrap()),
        ) {
            let ct = MetadataCiphertext { c: c.try_into().expect("c length"), cp };
            let restored = MetadataCiphertext::from_bytes(&ct.as_bytes()).expect("valid bytes");
            prop_assert_eq!(ct.as_bytes(), restored.as_bytes());
        }

        #[test]
        fn test_envelope_serde_roundtrip(
            c1 in prop::collection::vec(any::<u8>(), DH_AKEM_ENCAPS_SECRET_LEN),
            cp_a in prop::collection::vec(any::<u8>(), 0..128),
            c2 in prop::collection::vec(any::<u8>(), LEN_MLKEM_SHAREDSECRET_ENCAPS),
            c in prop::collection::vec(any::<u8>(), LEN_XWING_SHAREDSECRET_ENCAPS),
            cp_b in prop::collection::vec(any::<u8>(), LEN_METADATA_CIPHERTEXT)
            .prop_map(|v| v.try_into().unwrap()),
            mgdh_pubkey in prop::array::uniform32(any::<u8>()),
            mgdh in prop::array::uniform32(any::<u8>()),
        ) {
            let env = Envelope {
                ct_apke: message_ct(c1, cp_a, c2),
                ct_pke: MetadataCiphertext { c: c.try_into().expect("c length"), cp: cp_b },
                mgdh_pubkey,
                mgdh,
            };
            let json = serde_json::to_string(&env).expect("serialize");
            let restored: Envelope = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(env.ct_apke.as_bytes(), restored.ct_apke.as_bytes());
            prop_assert_eq!(env.ct_pke.as_bytes(), restored.ct_pke.as_bytes());
            prop_assert_eq!(env.mgdh_pubkey, restored.mgdh_pubkey);
            prop_assert_eq!(env.mgdh, restored.mgdh);
        }

        #[test]
        fn test_fetch_challenge_response_serde_roundtrip(
            enc_ids in prop::collection::vec(
                prop::collection::vec(any::<u8>(), LEN_KMID), 0..6),
            pmgdhs in prop::collection::vec(prop::array::uniform32(any::<u8>()), 0..6),
        ) {
            let n = enc_ids.len().min(pmgdhs.len());
            let messages: Vec<FetchResponse> = (0..n)
                .map(|i| FetchResponse {
                    enc_id: enc_ids[i].clone().try_into().expect("enc_id length"),
                    pmgdh: pmgdhs[i],
                })
                .collect();
            let resp = crate::wire::core::MessageChallengeFetchResponse { count: n, messages };

            let json = serde_json::to_string(&resp).expect("serialize");
            let restored: crate::wire::core::MessageChallengeFetchResponse =
                serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(restored.count, resp.count);
            prop_assert_eq!(restored.messages.len(), resp.messages.len());
            for (a, b) in resp.messages.iter().zip(restored.messages.iter()) {
                prop_assert_eq!(a.enc_id, b.enc_id);
                prop_assert_eq!(a.pmgdh, b.pmgdh);
            }
        }
    }
}
