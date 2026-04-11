#![no_std]
extern crate alloc;

pub mod api;
mod ciphertext;
mod constants;
pub mod keys;
pub mod messages;
pub mod primitives;
pub mod server;
pub mod setup;
mod traits;

pub mod journalist;
pub mod source;

pub use constants::{LEN_DH_ITEM, LEN_MLKEM_ENCAPS_KEY, LEN_XWING_ENCAPS_KEY};

pub use ciphertext::{Envelope, FetchResponse, Plaintext};

pub use keys::{
    DhAkemKeyPair, DhFetchKeyPair, Enrollment, KeyBundlePublic, KeyPair, MlKem768KeyPair,
    SessionStorage, SignedKeyBundlePublic, SignedLongtermPubKeyBytes, SigningKeyPair,
};

pub use traits::{Enrollable, JournalistPublic, UserPublic, UserSecret};

pub use journalist::{Journalist, JournalistPublicView};
pub use source::{Source, SourcePublicView};

pub(crate) use keys::MessageKeyBundle;
pub(crate) use traits::private;

// Primitives for signing
pub mod sign;
pub use sign::{
    DomainTag, FpfOnNewsroom, JournalistEphemeralKey, JournalistLongTermKey, NewsroomOnJournalist,
    Signature, SigningKey, VerifyingKey,
};

pub mod storage;

pub mod encrypt_decrypt;
pub mod message;
pub mod metadata;
