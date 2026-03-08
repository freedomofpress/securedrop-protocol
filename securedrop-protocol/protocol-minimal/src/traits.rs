use crate::SelfSignature;
use crate::VerifyingKey;
use crate::primitives::dh_akem::DhAkemPrivateKey;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::mlkem::MLKEM768PublicKey;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::xwing::XWingPublicKey;
use alloc::vec::Vec;

use crate::ciphertext::Plaintext;
use crate::key_types::{
    Enrollment, MessageKeyBundle, SignedKeyBundlePublic, SignedLongtermPubKeyBytes,
};

// Seal Secret user traits behind a private module so that others can't access or implement them
// This could be more restricted than pub(crate), except we also use it for testing
pub(crate) mod private {
    pub trait Sealed {}
}

////////////////////////
///
/// Users have the following (public traits) in common:
/// They expose a fetch pubkey, a message auth pubkey
/// (implicit authentication),
/// and a collection of KeyBundles (tuples of keys - a keybundle contains
/// all the key material required to send a message to a given user).
/// A Source has a KeyBundle collection of size 1.
/// A Journalist has KeyBundle collection of size > 1.
/// Some users (Sources) use a key from their message bundle as
/// their message auth key.
pub trait UserPublic {
    fn fetch_pk(&self) -> &DHPublicKey;
    fn message_auth_pk(&self) -> &DhAkemPublicKey;
    fn message_psk_pk(&self) -> &MLKEM768PublicKey;
    fn message_metadata_pk(&self) -> &XWingPublicKey;
    fn message_enc_pk(&self) -> &DhAkemPublicKey;
}

pub trait JournalistPublic: UserPublic {
    fn verifying_key(&self) -> &VerifyingKey;
    fn self_signature(&self) -> &SelfSignature;
    fn signed_keybytes(&self) -> &SignedLongtermPubKeyBytes;
}

pub trait Enrollable: private::Sealed {
    fn signing_key(&self) -> &VerifyingKey;
    fn enroll(&self) -> Enrollment;
    fn signed_keybundles(&self) -> impl Iterator<Item = SignedKeyBundlePublic>;
}

/// Users have the following (secret traits) in common:
/// They have a fetching keypair used to retrieve messages;
/// They have a message authentication keypair used to implicitly
/// authenticate their messages (via DH-AKEM);
/// They can index a KeyBundle (tuple) and use it to attempt to
/// decrypt a message.
pub trait UserSecret: private::Sealed {
    fn num_bundles(&self) -> usize;
    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey);
    fn message_auth_keypair(&self) -> (&DhAkemPrivateKey, &DhAkemPublicKey);
    fn build_message(&self, message: Vec<u8>) -> Plaintext;
    fn keybundles(&self) -> impl Iterator<Item = &MessageKeyBundle>;
}
