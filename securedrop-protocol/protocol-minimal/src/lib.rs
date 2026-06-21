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
pub mod primitives;
pub mod server;
pub mod setup;
mod traits;
pub mod wire;
pub mod wire_format;

pub mod journalist;
pub mod source;

pub use ciphertext::{Envelope, FetchResponse, Plaintext};

pub use keys::{
    DhFetchKeyPair, Enrollment, KeyBundlePublic, KeyPair, SessionStorage, SignedKeyBundlePublic,
    SignedLongtermPubKeyBytes, SigningKeyPair,
};
pub use primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
pub use primitives::x25519::DH_PUBLIC_KEY_LEN;
pub use primitives::xwing::XWING_PUBLIC_KEY_LEN;

pub use traits::{Enrollable, JournalistPublic, UserPublic, UserSecret};

pub use journalist::{Journalist, JournalistPublicView};
pub use source::{Source, SourcePublicView};

pub(crate) use keys::MessageKeyBundle;

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

// Do not make this module public or re-export it anywhere!
/// It uses the [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed)
/// to gate features that downstream crates should not implement.
mod sealed;
