use crate::message::MessageCiphertext;
use crate::metadata::{MetadataCiphertext, MetadataPublicKey};
use crate::primitives::provider::constants::LEN_KMID;
use crate::primitives::x25519::{DH_SHARED_SECRET_LEN, DHPublicKey};
use crate::size::PlaintextWire;
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
    pub(crate) mgdh_pubkey: [u8; DHPublicKey::SIZE],

    /// `Z = (pk_R^fetch)^x`: DH share for fetching
    #[cfg_attr(not(hax), serde(with = "hex_array"))]
    pub(crate) mgdh: [u8; DHPublicKey::SIZE],
}

impl Envelope {
    // Used for benchmarks - see wasm_bindgen
    pub const SIZE: usize =
        MessageCiphertext::SIZE + MetadataCiphertext::SIZE + crate::size::CLUE_SIZE;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plaintext {
    /// Metadata key: $pk_S^{PKE}$ in the spec
    pub sender_reply_pubkey_hybrid: [u8; MetadataPublicKey::SIZE],
    /// Fetching key: $pk_S^{fetch}$ in the spec
    pub sender_fetch_key: [u8; DHPublicKey::SIZE],
    /// Message
    pub msg: Vec<u8>,
}

impl Plaintext {
    // todo: when there is a msg_len header, add it's byte size here
    const HEADERS_TOTAL_BYTE_SIZE: usize = MetadataPublicKey::SIZE + DHPublicKey::SIZE;

    /// Construct new structured Plaintext object.
    /// Everything inside Plaintext will be serialized and AEAD-encrypted.
    pub fn new(
        message: Vec<u8>,
        reply_keys: Option<(&MetadataPublicKey, &DHPublicKey)>,
    ) -> Plaintext {
        if message.len() > PlaintextWire::SIZE - Plaintext::HEADERS_TOTAL_BYTE_SIZE {
            // TODO: something more graceful
            panic!("Message is too long");
        }

        if let Some((md_key, fetch_key)) = reply_keys {
            let mut reply_key_pq_hybrid = [0u8; MetadataPublicKey::SIZE];
            reply_key_pq_hybrid.copy_from_slice(md_key.as_bytes());

            return Plaintext {
                sender_reply_pubkey_hybrid: reply_key_pq_hybrid,
                sender_fetch_key: fetch_key.into_bytes(),
                msg: message,
            };
        } else {
            // No reply keys attached
            return Plaintext {
                sender_reply_pubkey_hybrid: [0u8; MetadataPublicKey::SIZE],
                sender_fetch_key: [0u8; DHPublicKey::SIZE],
                msg: message,
            };
        }
    }

    /// Pad and serialize Plaintext.
    /// TODO (toy padding)
    pub fn encode_padded(&self) -> PlaintextWire {
        let mut buf = alloc::vec![0u8; PlaintextWire::SIZE];

        buf[0..MetadataPublicKey::SIZE].copy_from_slice(&self.sender_reply_pubkey_hybrid);

        buf[MetadataPublicKey::SIZE..Plaintext::HEADERS_TOTAL_BYTE_SIZE]
            .copy_from_slice(&self.sender_fetch_key);
        buf[Plaintext::HEADERS_TOTAL_BYTE_SIZE
            ..Plaintext::HEADERS_TOTAL_BYTE_SIZE + self.msg.len()]
            .copy_from_slice(&self.msg);

        PlaintextWire::new(buf)
    }

    // Toy parsing only
    pub fn from_wire_bytes(pt_wire_bytes: PlaintextWire) -> Result<Self, Error> {
        let mut pt_bytes = Self::strip_padding(pt_wire_bytes)?;

        let mut sender_reply_pubkey_hybrid = [0u8; MetadataPublicKey::SIZE];
        sender_reply_pubkey_hybrid.copy_from_slice(&pt_bytes[0..MetadataPublicKey::SIZE]);

        let mut sender_fetch_key = [0u8; DHPublicKey::SIZE];
        sender_fetch_key.copy_from_slice(
            &pt_bytes[MetadataPublicKey::SIZE..MetadataPublicKey::SIZE + DHPublicKey::SIZE],
        );

        // to change when length header is added
        debug_assert_eq!(
            Plaintext::HEADERS_TOTAL_BYTE_SIZE,
            MetadataPublicKey::SIZE + DHPublicKey::SIZE
        );

        // todo: putting the msg before the keys is a future optimization
        let msg = pt_bytes.split_off(Plaintext::HEADERS_TOTAL_BYTE_SIZE);

        Ok(Plaintext {
            sender_reply_pubkey_hybrid,
            sender_fetch_key,
            msg: msg,
        })
    }

    /// Strip the trailing zero padding applied at submission time.
    ///
    /// TODO: Fix the padding scheme so if a message actually ends in NUL bytes
    /// we don't lose data. We should length prefix it instead?
    fn strip_padding(pt_wire: PlaintextWire) -> Result<Vec<u8>, Error> {
        // todo: let end = pt_wire.parse_len() and implement header field
        let mut msg_vec = pt_wire.into_vec();

        let end = msg_vec.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

        msg_vec.truncate(end);

        Ok(msg_vec)
    }

    pub fn len(&self) -> usize {
        &self.sender_reply_pubkey_hybrid.len() + &self.msg.len() + &self.sender_fetch_key.len()
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
    use crate::size::CiphertextWire;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_message_ciphertext_byte_roundtrip(
            c1 in any::<[u8; DH_AKEM_ENCAPS_SECRET_LEN]>(),
            cp in prop::collection::vec(any::<u8>(), CiphertextWire::SIZE),
            c2 in any::<[u8; LEN_MLKEM_SHAREDSECRET_ENCAPS]>(),
        ) {
            let ct = MessageCiphertext{c1, cp: CiphertextWire::new(cp), c2};
            let restored = MessageCiphertext::from_bytes(&ct.as_bytes()).expect("valid bytes");
            prop_assert_eq!(ct.as_bytes(), restored.as_bytes());
        }

        #[test]
        fn test_metadata_ciphertext_byte_roundtrip(
            c in any::<[u8; LEN_XWING_SHAREDSECRET_ENCAPS]>(),
            cp in any::<[u8; LEN_METADATA_CIPHERTEXT]>()
            .prop_map(|v| v.try_into().unwrap()),
        ) {
            let ct = MetadataCiphertext { c, cp };
            let restored = MetadataCiphertext::from_bytes(&ct.as_bytes()).expect("valid bytes");
            prop_assert_eq!(ct.as_bytes(), restored.as_bytes());
        }

        #[test]
        fn test_envelope_serde_roundtrip(
            c1 in any::<[u8; DH_AKEM_ENCAPS_SECRET_LEN]>(),
            cp_a in prop::collection::vec(any::<u8>(), CiphertextWire::SIZE),
            c2 in any::<[u8; LEN_MLKEM_SHAREDSECRET_ENCAPS]>(),
            c in any::<[u8; LEN_XWING_SHAREDSECRET_ENCAPS]>(),
            cp_b in any::<[u8; LEN_METADATA_CIPHERTEXT]>()
            .prop_map(|v| v.try_into().unwrap()),
            mgdh_pubkey in prop::array::uniform32(any::<u8>()),
            mgdh in prop::array::uniform32(any::<u8>()),
        ) {
            let env = Envelope {
                ct_apke: MessageCiphertext {c1, cp: CiphertextWire::new(cp_a), c2},
                ct_pke: MetadataCiphertext { c, cp: cp_b },
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
                any::<[u8; LEN_KMID]>(), 0..6),
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
