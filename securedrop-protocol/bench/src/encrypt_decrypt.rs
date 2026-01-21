extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use js_sys::{Array, Uint8Array};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use wasm_bindgen::prelude::*;

use securedrop_protocol_minimal::encrypt_decrypt::{
    compute_fetch_challenges, decrypt, encrypt, solve_fetch_challenges,
};
use securedrop_protocol_minimal::types::{
    Envelope, FetchResponse, Journalist, Plaintext, ServerMessageStore, Source, User,
};

use securedrop_protocol_minimal::encrypt_decrypt::{
    LEN_DH_ITEM, LEN_MLKEM_ENCAPS_KEY, LEN_XWING_ENCAPS_KEY,
};

#[inline]
fn rng_from_seed(seed32: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed32)
}

/* ========= Opaque wrappers ========= */

#[wasm_bindgen]
pub struct WSource {
    inner: Source,
}

#[wasm_bindgen]
impl WSource {
    /// Construct a Source (actor setup randomness is outside timed paths).
    #[wasm_bindgen(constructor)]
    pub fn new() -> WSource {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed");
        let mut rng = rng_from_seed(seed);
        WSource {
            inner: Source::new(&mut rng),
        }
    }
}

#[wasm_bindgen]
pub struct WJournalist {
    inner: Journalist,
}

#[wasm_bindgen]
impl WJournalist {
    /// Construct a Journalist with `num_keybundles` short-lived bundles.
    #[wasm_bindgen(constructor)]
    pub fn new(num_keybundles: usize) -> WJournalist {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed");
        let mut rng = rng_from_seed(seed);
        WJournalist {
            inner: Journalist::new(&mut rng, num_keybundles),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn keybundles(&self) -> usize {
        self.inner.get_all_keys().len()
    }
}

#[wasm_bindgen]
pub struct WEnvelope {
    inner: Envelope,
}

impl From<Envelope> for WEnvelope {
    fn from(inner: Envelope) -> Self {
        WEnvelope { inner }
    }
}

#[wasm_bindgen]
impl WEnvelope {
    /// Size hint to mirror the Rust bench’s “sink” usage.
    pub fn size_hint(&self) -> usize {
        self.inner.cmessage_len() + self.inner.cmetadata_len()
    }
}

#[wasm_bindgen]
pub struct WFetchResponse {
    inner: FetchResponse,
}
impl From<FetchResponse> for WFetchResponse {
    fn from(inner: FetchResponse) -> Self {
        WFetchResponse { inner }
    }
}

#[wasm_bindgen]
pub struct WStoreEntry {
    inner: ServerMessageStore,
}

#[wasm_bindgen]
impl WStoreEntry {
    /// Build a server store entry from a 16-byte message_id and a WEnvelope.
    #[wasm_bindgen(constructor)]
    pub fn new(message_id_16: &[u8], envelope: &WEnvelope) -> WStoreEntry {
        assert_eq!(message_id_16.len(), 16, "message_id must be 16 bytes");
        let mut id = [0u8; 16];
        id.copy_from_slice(message_id_16);
        WStoreEntry {
            inner: ServerMessageStore::new(id, envelope.inner.clone()),
        }
    }
}

/// `seed32` must be exactly 32 bytes.
#[wasm_bindgen]
pub fn encrypt_once(
    seed32: &[u8],
    sender: &WSource,
    recipient: &WJournalist,
    recipient_bundle_index: usize,
    msg: &[u8],
) -> WEnvelope {
    assert_eq!(seed32.len(), 32, "seed32 must be 32 bytes");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed32);

    // build plaintext object
    let mut pq = [0u8; LEN_MLKEM_ENCAPS_KEY];
    pq.copy_from_slice(&sender.inner.keys.pq_kem_psk_pk);

    let mut hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
    hybrid.copy_from_slice(&sender.inner.keys.hybrid_md_pk);

    let mut fetch = [0u8; LEN_DH_ITEM];
    fetch.copy_from_slice(sender.inner.get_fetch_pk());

    // construct a Plaintext object (previously just message bytes)
    let plaintext = Plaintext {
        sender_reply_pubkey_pq_psk: pq,
        sender_reply_pubkey_hybrid: hybrid,
        sender_fetch_key: fetch,
        msg: msg.to_vec(),
    };

    let env = bench_encrypt(
        seed,
        &sender.inner,
        &recipient.inner,
        recipient_bundle_index,
        &plaintext.to_bytes(),
    );
    env.into()
}

/// Returns message bytes from plaintext.
/// TODO: can also return a WPlaintext object to access more fields in benchmarking
#[wasm_bindgen]
pub fn decrypt_once(recipient: &WJournalist, envelope: &WEnvelope) -> Vec<u8> {
    let pt: Plaintext = bench_decrypt(&recipient.inner, &envelope.inner);

    // sanity
    assert_eq!(
        pt.msg.len(),
        pt.len() - (LEN_DH_ITEM + LEN_MLKEM_ENCAPS_KEY + LEN_XWING_ENCAPS_KEY)
    );

    // this was just a string, now it's a plaintext struct.
    // was hoping to avoid the entire wplaintext wrapper struct and return the message bytes and not change anything else.
    pt.msg
}

/// Build challenges for fetch
#[wasm_bindgen]
pub fn compute_fetch_challenges_once(
    seed32: &[u8],
    entries: Box<[WStoreEntry]>,
    total_responses: usize,
) -> Box<[WFetchResponse]> {
    assert_eq!(seed32.len(), 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed32);
    let mut rng = rng_from_seed(seed);

    let store: Vec<ServerMessageStore> = entries.into_vec().into_iter().map(|w| w.inner).collect();
    compute_fetch_challenges(&mut rng, &store, total_responses)
        .into_iter()
        .map(WFetchResponse::from)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[wasm_bindgen]
pub fn fetch_once(recipient: &WJournalist, challenges: Box<[WFetchResponse]>) -> Array {
    let inner: Vec<FetchResponse> = challenges.into_vec().into_iter().map(|w| w.inner).collect();
    let ids: Vec<Vec<u8>> = bench_fetch(&recipient.inner, inner);

    // Build Array<Uint8Array>
    let out = Array::new();
    for id in ids {
        // Each message_id is 16 bytes
        let u8arr = Uint8Array::from(id.as_slice());
        out.push(&u8arr.into());
    }
    out
}

// Benchmark functions

// Begin benchmark functions
pub fn bench_encrypt(
    seed32: [u8; 32],
    sender: &dyn User,
    recipient: &dyn User,
    recipient_bundle_index: usize,
    plaintext: &[u8],
) -> Envelope {
    let mut rng = ChaCha20Rng::from_seed(seed32);
    encrypt(
        &mut rng,
        sender,
        plaintext,
        recipient,
        Some(recipient_bundle_index),
    )
}

pub fn bench_decrypt(recipient: &dyn User, envelope: &Envelope) -> Plaintext {
    decrypt(recipient, envelope)
}

pub fn bench_fetch(recipient: &dyn User, challenges: Vec<FetchResponse>) -> Vec<Vec<u8>> {
    solve_fetch_challenges(recipient, challenges)
}
