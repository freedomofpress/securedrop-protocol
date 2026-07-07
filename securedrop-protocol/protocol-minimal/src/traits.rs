use crate::VerifyingKey;
use crate::message::{MessagePrivateKey, MessagePublicKey};
use crate::metadata::MetadataPublicKey;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;

use crate::sign::{JournalistEphemeralKey, JournalistLongTermKey, Signature};
use alloc::vec::Vec;

use crate::keys::{
    Enrollment, KeyBundlePublic, MessageKeyBundle, SignedKeyBundlePublic, SignedLongtermPubKeyBytes,
};

// Sealed traits that downstream crates should not implement.
// Do not re-export!
use crate::sealed;

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
    /// The long-term SD-APKE public key `pk^APKE`.
    fn message_auth_pk(&self) -> &MessagePublicKey;
    fn message_metadata_pk(&self) -> &MetadataPublicKey;
    /// The ephemeral SD-APKE public key `pk^{APKE_E}` from a key bundle.
    fn message_enc_pk(&self) -> &MessagePublicKey;
}

pub trait JournalistPublic: UserPublic {
    fn verifying_key(&self) -> &VerifyingKey;
    fn self_signature(&self) -> &Signature<JournalistLongTermKey>;
    fn signed_keybytes(&self) -> &SignedLongtermPubKeyBytes;
    fn ephemeral_bundle(&self) -> &KeyBundlePublic;
    fn ephemeral_signature(&self) -> &Signature<JournalistEphemeralKey>;
}

#[cfg(not(hax))]
pub trait Enrollable: sealed::Sealed {
    // sealed traits don't play nice with hax right now, so this is a workaround
    fn signing_key(&self) -> &VerifyingKey;
    fn enroll(&self) -> Enrollment;
    /// Each item is a [`SignedKeyBundlePublic`]: the public keys together with the
    /// journalist's self-signature over them.
    fn signed_keybundles(&self) -> Vec<SignedKeyBundlePublic>;
}

#[cfg(hax)]
pub trait Enrollable {
    fn signing_key(&self) -> &VerifyingKey;
    fn enroll(&self) -> Enrollment;
    /// Each item is a [`SignedKeyBundlePublic`]: the public keys together with the
    /// journalist's self-signature over them.
    fn signed_keybundles(&self) -> Vec<SignedKeyBundlePublic>;
}

/// Users have the following (secret traits) in common:
/// They have a fetching keypair used to retrieve messages;
/// They have a message authentication keypair used to implicitly
/// authenticate their messages (via DH-AKEM);
/// They can index a KeyBundle (tuple) and use it to attempt to
/// decrypt a message.
#[cfg(not(hax))]
pub trait UserSecret: sealed::Sealed {
    fn num_bundles(&self) -> usize;
    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey);
    /// The long-term SD-APKE private key `sk^APKE`.
    fn message_auth_key(&self) -> &MessagePrivateKey;
    /// The holder's own long-term SD-APKE public key `pk^APKE`.
    fn own_message_auth_pk(&self) -> &MessagePublicKey;
    fn own_message_reply_keys(&self) -> Option<(&MetadataPublicKey, &DHPublicKey)>;
    fn keybundles(&self) -> Vec<&MessageKeyBundle>;
}

#[cfg(hax)]
pub trait UserSecret {
    fn num_bundles(&self) -> usize;
    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey);
    /// The long-term SD-APKE private key `sk^APKE`.
    fn message_auth_key(&self) -> &MessagePrivateKey;
    /// The holder's own long-term SD-APKE public key `pk^APKE`.
    fn own_message_auth_pk(&self) -> &MessagePublicKey;
    fn own_message_reply_keys(&self) -> Option<(&MetadataPublicKey, &DHPublicKey)>;
    fn keybundles(&self) -> Vec<&MessageKeyBundle>;
}

// hax doesn't work well with sealed trait pattern right now
#[cfg(not(hax))]
pub trait RestrictedApi: sealed::Sealed {}

#[cfg(hax)]
pub trait RestrictedApi {}
