#![no_std]
// Deny direct access to system randomness except in tests.
// See clippy.toml
// hax breaks on these clippy statements
#![cfg_attr(not(hax), deny(clippy::disallowed_types, clippy::disallowed_methods))]
#![cfg_attr(all(not(hax), test), allow(clippy::disallowed_types))]
#![cfg_attr(all(not(hax), test), allow(clippy::disallowed_methods))]
extern crate alloc;

pub mod api;
mod ciphertext;
pub mod keys;
pub(crate) mod primitives;
pub mod schemes;
pub mod server;
pub mod setup;
mod traits;
pub mod wire;

pub mod journalist;
pub mod source;

pub use schemes::{challenge, message, metadata, sign};

pub use ciphertext::{Envelope, FetchResponse, Plaintext};

pub use keys::{DhFetchKeyPair, KeyBundlePublic, KeyPair, SessionStorage};
pub use wire::bundle::{SignedKeyBundlePublic, SignedLongtermKeyBundle};
pub use wire::enrollment::Enrollment;

pub use primitives::ristretto255::DHPublicKey;

pub use traits::{Enrollable, JournalistPublic, UserPublic, UserSecret};

pub use journalist::{
    EphemeralBundleBytes, Journalist, JournalistLongTermBytes, JournalistPublicView,
};
pub use source::{Source, SourcePublicView};

pub(crate) use keys::MessageKeyBundle;

// Primitives for signing
pub use sign::{
    DomainTag, FpfOnNewsroom, JournalistEphemeralKey, JournalistLongTermKey, NewsroomOnJournalist,
    Signature, SigningKey, VerifyingKey,
};

pub mod storage;

pub mod encrypt_decrypt;

// Do not make this module public or re-export it anywhere!
/// It uses the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed)
/// to gate features that downstream crates should not implement.
mod sealed;
