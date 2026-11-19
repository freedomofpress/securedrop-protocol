mod newsroom;

use crate::primitives::ristretto255::{DHPrivateKey, DHPublicKey};
use crate::sign::{FpfOnNewsroom, Signature, VerifyingKey};

pub mod bundle;
pub mod fpf;

pub use bundle::KeyBundlePublic;
pub(crate) use bundle::{LongtermKeyBundle, MessageKeyBundle};
pub use fpf::FPFKeyPair;

/// Generic KeyPair
pub struct KeyPair<SK, PK> {
    pub(crate) sk: SK,
    pub(crate) pk: PK,
}

// silly name but include "fetch" for disambiguation with dh-akem.
// eventually: ristretto255
pub type DhFetchKeyPair = KeyPair<DHPrivateKey, DHPublicKey>;

pub use newsroom::NR_ID;
pub use newsroom::NewsroomKeyPair;
