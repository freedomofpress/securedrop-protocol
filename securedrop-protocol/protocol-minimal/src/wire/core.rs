use crate::message::MessageCiphertext;
use crate::message::MessagePublicKey;
use crate::metadata::MetadataCiphertext;
use crate::primitives::provider::constants::LEN_KMID;
use crate::primitives::ristretto255::DHPublicKey;
use crate::sign::{
    FpfOnNewsroom, JournalistLongTermKey, NewsroomOnJournalist, Signature, VerifyingKey,
};
use crate::wire::bundle::{SignedKeyBundlePublic, SignedLongtermKeyBundle};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A journalist's long-term public key material, as carried in the
/// [`WelcomeBundle`].
///
/// Combined with a one-time [`SignedKeyBundlePublic`] (fetched separately
/// by an ephemeral key request) to reconstruct a `JournalistPublicView` for
/// encryption.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct JournalistLongTermView {
    pub vk: VerifyingKey,
    pub signed_longterm_key_bundle: SignedLongtermKeyBundle,
    pub nr_signature: Signature<NewsroomOnJournalist>,
}

/// The newsroom "welcome bundle" (step 5): this is everything a sender needs to
/// begin - the newsroom verifying key, FPF's signature over it, and the roster
/// of journalists' long-term keys/signatures.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct WelcomeBundle {
    pub newsroom_verifying_key: VerifyingKey,
    pub fpf_sig: Signature<FpfOnNewsroom>,
    pub journalists: Vec<JournalistLongTermView>,
}

/// One journalist's one-time (ephemeral) key bundle. `vk` identifies which
/// journalist - the server consumes the bundle when it serves it.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct JournalistEphemeralKeys {
    pub vk: VerifyingKey,
    pub ephemeral: SignedKeyBundlePublic,
}

/// User (source or journalist) fetches message IDs
///
/// This corresponds to step 7 in the spec.
pub struct MessageChallengeFetchRequest {}

/// Server returns encrypted message IDs
///
/// This corresponds to step 7 in the spec.
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct MessageChallengeFetchResponse {
    /// Number of message entries returned
    /// TODO: constant size array
    pub count: usize,
    /// Array of FetchResponses, aka (enc_id, pmgdh) pairs, where encid/cid is encrypted message ID and pmgdh (Q) is the group DH share
    pub messages: Vec<FetchResponse>,
}

/// User fetches a specific message by ID
///
/// This corresponds to step 8 and 10 in the spec.
pub struct MessageFetchRequest {
    /// Message ID to fetch
    pub message_id: Uuid,
}

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

#[derive(Clone, Debug)]
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct FetchResponse {
    #[cfg_attr(not(hax), serde(with = "hex_array"))]
    pub(crate) enc_id: [u8; LEN_KMID], // aka kmid
    // `Q_k`, the per-request clue
    pub(crate) pmgdh: DHPublicKey,
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: DHPublicKey) -> Self {
        Self { enc_id, pmgdh }
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
    pub(crate) mgdh_pubkey: DHPublicKey,

    /// `Z = (pk_R^fetch)^x`: DH share for fetching
    pub(crate) mgdh: DHPublicKey,
}

impl Envelope {
    // Used for benchmarks - see wasm_bindgen
    // Marked as lax to handle the variable size of cp in MessageCiphertext
    // TODO(#229): This should be removed when cp has a fixed size
    #[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::LEN_METADATA_CIPHERTEXT;
    use crate::primitives::dh_akem::DH_AKEM_ENCAPS_SECRET_LEN;
    use crate::primitives::mlkem::LEN_MLKEM_SHAREDSECRET_ENCAPS;
    use crate::primitives::ristretto255::random_dh_public_key;
    use crate::primitives::xwing::LEN_XWING_SHAREDSECRET_ENCAPS;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn message_ct(c1: Vec<u8>, cp: Vec<u8>, c2: Vec<u8>) -> MessageCiphertext {
        MessageCiphertext {
            c1: c1.try_into().expect("c1 length"),
            cp,
            c2: c2.try_into().expect("c2 length"),
        }
    }

    proptest! {
        #[test]
        fn test_envelope_serde_roundtrip(
            c1 in prop::collection::vec(any::<u8>(), DH_AKEM_ENCAPS_SECRET_LEN),
            cp_a in prop::collection::vec(any::<u8>(), 0..128),
            c2 in prop::collection::vec(any::<u8>(), LEN_MLKEM_SHAREDSECRET_ENCAPS),
            c in prop::collection::vec(any::<u8>(), LEN_XWING_SHAREDSECRET_ENCAPS),
            cp_b in prop::collection::vec(any::<u8>(), LEN_METADATA_CIPHERTEXT)
            .prop_map(|v| v.try_into().unwrap()),
            rng_seed: u64,
        ) {
            // X and Z must be valid ristretto255 encodings
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let mgdh_pubkey = random_dh_public_key(&mut rng);
            let mgdh = random_dh_public_key(&mut rng);

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
            prop_assert_eq!(env.mgdh_pubkey.into_bytes(), restored.mgdh_pubkey.into_bytes());
            prop_assert_eq!(env.mgdh.into_bytes(), restored.mgdh.into_bytes());
        }

        #[test]
        fn test_fetch_challenge_response_serde_roundtrip(
            enc_ids in prop::collection::vec(
                prop::collection::vec(any::<u8>(), LEN_KMID), 0..6),
            rng_seed: u64,
        ) {
            // pmgdh is a ristretto255 group element
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let messages: Vec<FetchResponse> = enc_ids
                .iter()
                .map(|enc_id| FetchResponse {
                    enc_id: enc_id.clone().try_into().expect("enc_id length"),
                    pmgdh: random_dh_public_key(&mut rng),
                })
                .collect();
            let n = messages.len();
            let resp = crate::wire::core::MessageChallengeFetchResponse { count: n, messages };

            let json = serde_json::to_string(&resp).expect("serialize");
            let restored: crate::wire::core::MessageChallengeFetchResponse =
                serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(restored.count, resp.count);
            prop_assert_eq!(restored.messages.len(), resp.messages.len());
            for (a, b) in resp.messages.iter().zip(restored.messages.iter()) {
                prop_assert_eq!(a.enc_id, b.enc_id);
                prop_assert_eq!(a.pmgdh.into_bytes(), b.pmgdh.into_bytes());
            }
        }
    }
}
