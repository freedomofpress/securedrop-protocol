use crate::constants::*;
use alloc::vec::Vec;
use anyhow::Error;

#[derive(Debug, Clone)]
pub struct CombinedCiphertext {
    // dh-akem ss encaps (needed to decrypt message)
    pub(crate) message_dhakem_ss_encap: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS],

    // pq psk encap (needed to decaps psk)
    // also passed as part of `info` param during hpke.authopen
    pub(crate) message_pqpsk_ss_encap: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS],

    // authenc message ciphertext
    pub(crate) ct_message: Vec<u8>,
}

impl CombinedCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Store fixed-size arrays
        buf.extend_from_slice(&self.message_dhakem_ss_encap);
        buf.extend_from_slice(&self.message_pqpsk_ss_encap);

        // Store cmessage bytes
        buf.extend_from_slice(&self.ct_message);

        buf
    }

    pub fn len(&self) -> usize {
        self.to_bytes().len()
    }

    // TOY ONLY
    pub fn from_bytes(ct_bytes: &Vec<u8>) -> Result<Self, Error> {
        let mut dhakem_ss_encaps: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS] =
            [0u8; LEN_DHKEM_SHAREDSECRET_ENCAPS];

        let mut pqpsk_ss_encaps: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS] =
            [0u8; LEN_MLKEM_SHAREDSECRET_ENCAPS];

        dhakem_ss_encaps.copy_from_slice(&ct_bytes[0..LEN_DHKEM_SHAREDSECRET_ENCAPS]);

        pqpsk_ss_encaps.copy_from_slice(
            &ct_bytes[LEN_DHKEM_SHAREDSECRET_ENCAPS
                ..LEN_DHKEM_SHAREDSECRET_ENCAPS + LEN_MLKEM_SHAREDSECRET_ENCAPS],
        );

        let cmessage: Vec<u8> =
            ct_bytes[LEN_DHKEM_SHAREDSECRET_ENCAPS + LEN_MLKEM_SHAREDSECRET_ENCAPS..].to_vec();

        Ok(CombinedCiphertext {
            message_dhakem_ss_encap: dhakem_ss_encaps,
            message_pqpsk_ss_encap: pqpsk_ss_encaps,
            ct_message: (cmessage),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Envelope {
    // (message_ciphertext || message_dhakem_ss_encap || msg_psk_ss_encap)
    // see CombinedCiphertext
    pub(crate) cmessage: Vec<u8>,

    // baseenc "metadata", aka sender pubkey
    pub(crate) cmetadata: Vec<u8>,

    // "metadata" encaps shared secret
    pub(crate) metadata_encap: [u8; LEN_XWING_SHAREDSECRET_ENCAPS],

    // clue material
    pub(crate) mgdh_pubkey: [u8; LEN_DH_ITEM],
    pub(crate) mgdh: [u8; LEN_DH_ITEM],
}

impl Envelope {
    // Used for benchmarks - see wasm_bindgen
    pub fn size_hint(&self) -> usize {
        self.cmessage.len() + self.cmetadata.len()
    }

    pub fn cmessage_len(&self) -> usize {
        self.cmessage.len()
    }

    // sender dh-akem pubkey bytes
    pub fn cmetadata_len(&self) -> usize {
        self.cmetadata.len()
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
    pub fn from_bytes(pt_bytes: &Vec<u8>) -> Result<Self, Error> {
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

#[derive(Clone)]
pub struct FetchResponse {
    pub(crate) enc_id: [u8; LEN_KMID],   // aka kmid
    pub(crate) pmgdh: [u8; LEN_DH_ITEM], // aka per-request clue
}

impl FetchResponse {
    pub fn new(enc_id: [u8; LEN_KMID], pmgdh: [u8; LEN_DH_ITEM]) -> Self {
        Self {
            enc_id: enc_id,
            pmgdh: pmgdh,
        }
    }
}
