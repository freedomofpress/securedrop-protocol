extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use js_sys::{Array, Uint8Array};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use securedrop_protocol_minimal::encrypt_decrypt::{
    compute_fetch_challenges, decrypt, encrypt, solve_fetch_challenges,
};
use securedrop_protocol_minimal::types::{
    Envelope, FetchResponse, Journalist, Plaintext, Source, UserPublic, UserSecret,
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
        self.inner.num_bundles()
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

// Note: this no longer wraps an inner type, but since wasm-bindgen
// can't handle hashmaps, a k,v pair is passed using this wrapper.
#[wasm_bindgen]
pub struct WStoreEntry {
    pub(crate) message_id: Box<[u8]>,
    pub(crate) envelope: WEnvelope,
}

#[wasm_bindgen]
impl WStoreEntry {
    /// Build a server store entry from a 16-byte message_id and a WEnvelope.
    #[wasm_bindgen(constructor)]
    pub fn new(message_id_16: &[u8], envelope: WEnvelope) -> WStoreEntry {
        assert_eq!(message_id_16.len(), 16, "message_id must be 16 bytes");
        let mut id = [0u8; 16];
        id.copy_from_slice(message_id_16);
        Self {
            message_id: Box::new(id),
            envelope: envelope,
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
    let plaintext = sender.inner.build_message(msg.to_vec());

    let env = bench_encrypt(
        seed,
        &sender.inner,
        &recipient.inner.public(recipient_bundle_index),
        plaintext,
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

    let mut store: HashMap<Uuid, Envelope> = HashMap::new();
    let _ = entries.into_vec().into_iter().map(|entry| {
        let box_mid = entry.message_id;
        let msg_uuid = Uuid::from_slice(&box_mid).unwrap();
        store.insert(msg_uuid, entry.envelope.inner)
    });

    compute_fetch_challenges(&mut rng, &store, total_responses)
        .into_iter()
        .map(WFetchResponse::from)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[wasm_bindgen]
pub fn fetch_once(recipient: &WJournalist, challenges: Box<[WFetchResponse]>) -> Array {
    let inner: Vec<FetchResponse> = challenges.into_vec().into_iter().map(|w| w.inner).collect();
    let ids: Vec<Uuid> = bench_fetch(&recipient.inner, inner);

    // Build Array<Uint8Array>
    let out = Array::new();
    for id in ids {
        // Each message_id is 16 bytes
        let id_bytes = id.as_bytes();
        let u8arr = Uint8Array::from(id_bytes.as_slice());
        out.push(&u8arr.into());
    }
    out
}

// Benchmark functions

// Begin benchmark functions
pub fn bench_encrypt<S: UserSecret, P: UserPublic>(
    seed32: [u8; 32],
    sender: &S,
    recipient: &P,
    plaintext: Plaintext,
) -> Envelope {
    let mut rng = ChaCha20Rng::from_seed(seed32);
    encrypt(&mut rng, sender, plaintext, recipient)
}

pub fn bench_decrypt<S: UserSecret>(recipient: &S, envelope: &Envelope) -> Plaintext {
    decrypt(recipient, envelope)
}

pub fn bench_fetch<S: UserSecret>(recipient: &S, challenges: Vec<FetchResponse>) -> Vec<Uuid> {
    solve_fetch_challenges(recipient, challenges)
}
