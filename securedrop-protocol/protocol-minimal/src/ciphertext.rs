use crate::message::MessageCiphertext;
use crate::metadata::MetadataCiphertext;
use crate::primitives::provider::constants::LEN_KMID;
use crate::primitives::x25519::{DH_PUBLIC_KEY_LEN, DH_SHARED_SECRET_LEN};
use crate::primitives::xwing::XWING_PUBLIC_KEY_LEN;
use alloc::vec::Vec;
use anyhow::Error;

/// The full submission `(C_S, X, Z)` sent from sender to server in step 6.
///
/// - `C_S = (ct^APKE, ct^PKE)`: the two ciphertexts
/// - `X = g^x`: ephemeral DH public key (hint)
/// - `Z = (pk_R^fetch)^x`: DH share for fetching (hint)
///
/// The server stores `(id, C_S, X, Z)` per message.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// `ct^APKE`: SD-APKE ciphertext `((c1, cp), c2)` - the encrypted message
    pub(crate) ct_apke: MessageCiphertext,

    /// `ct^PKE`: SD-PKE ciphertext `(c, c')` - the encrypted sender APKE public key
    pub(crate) ct_pke: MetadataCiphertext,

    /// `X = g^x`: ephemeral DH public key for the hint
    pub(crate) mgdh_pubkey: [u8; DH_PUBLIC_KEY_LEN],

    /// `Z = (pk_R^fetch)^x`: DH share for fetching
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct FetchResponse {
    pub(crate) enc_id: [u8; LEN_KMID],            // aka kmid
    pub(crate) pmgdh: [u8; DH_SHARED_SECRET_LEN], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; DH_SHARED_SECRET_LEN]) -> Self {
        Self { enc_id, pmgdh }
    }
}
