use crate::constants::{LEN_DH_ITEM, LEN_KMID, LEN_XWING_ENCAPS_KEY};
use crate::message::MessageCiphertext;
use crate::metadata::MetadataCiphertext;
use alloc::vec::Vec;
use anyhow::Error;

#[derive(Debug, Clone)]
pub struct Envelope {
    /// SD-APKE ciphertext `((c1, cp), c2)`
    pub(crate) ct_apke: MessageCiphertext,

    /// SD-PKE ciphertext `(c, c')`: encrypted sender APKE public key tuple
    pub(crate) ct_pke: MetadataCiphertext,

    // clue material
    pub(crate) mgdh_pubkey: [u8; LEN_DH_ITEM],
    pub(crate) mgdh: [u8; LEN_DH_ITEM],
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
    pub sender_reply_pubkey_hybrid: [u8; LEN_XWING_ENCAPS_KEY],
    /// Fetching key: $pk_S^{fetch}$ in the spec
    pub sender_fetch_key: [u8; LEN_DH_ITEM],
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
        LEN_XWING_ENCAPS_KEY + LEN_DH_ITEM + self.msg.len()
    }

    // Toy parsing only
    pub fn from_bytes(pt_bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;

        let mut sender_reply_pubkey_hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
        sender_reply_pubkey_hybrid
            .copy_from_slice(&pt_bytes[offset..offset + LEN_XWING_ENCAPS_KEY]);
        offset += LEN_XWING_ENCAPS_KEY;

        let mut sender_fetch_key = [0u8; LEN_DH_ITEM];
        sender_fetch_key.copy_from_slice(&pt_bytes[offset..offset + LEN_DH_ITEM]);
        offset += LEN_DH_ITEM;

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
    pub(crate) enc_id: [u8; LEN_KMID],   // aka kmid
    pub(crate) pmgdh: [u8; LEN_DH_ITEM], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; LEN_DH_ITEM]) -> Self {
        Self { enc_id, pmgdh }
    }
}
