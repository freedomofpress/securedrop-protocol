mod newsroom;

use crate::primitives::ristretto255::{DHPrivateKey, DHPublicKey};
use crate::sign::{FpfOnNewsroom, Signature, VerifyingKey};

pub mod bundle;
pub mod fpf;

pub use bundle::KeyBundlePublic;
pub(crate) use bundle::{LongtermKeyBundle, MessageKeyBundle, SignedMessageKeyBundle};
pub use fpf::FPFKeyPair;

/// Generic KeyPair
pub struct KeyPair<SK, PK> {
    pub(crate) sk: SK,
    pub(crate) pk: PK,
}

// silly name but include "fetch" for disambiguation with dh-akem.
// eventually: ristretto255
pub type DhFetchKeyPair = KeyPair<DHPrivateKey, DHPublicKey>;

// in memory session storage
pub struct SessionStorage {
    pub fpf_key: Option<VerifyingKey>,
    pub nr_key: Option<VerifyingKey>,
    pub fpf_signature: Option<Signature<FpfOnNewsroom>>,
}

pub use newsroom::NewsroomKeyPair;
