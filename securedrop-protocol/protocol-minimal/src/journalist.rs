use crate::VerifyingKey;
use crate::api::Client;
use crate::message::{MessageKeyPair, MessagePublicKey, keygen as message_keygen};
use crate::metadata::{MetadataPublicKey, keygen as metadata_keygen};
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::generate_dh_keypair;
use crate::sign::{JournalistEphemeralKey, JournalistLongTermKey, Signature, SigningKey};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::ciphertext::Plaintext;
use crate::keys::*;
use crate::traits::{Enrollable, JournalistPublic, RestrictedApi, UserPublic, UserSecret};

// caution: do not re-export!
use crate::sealed;

#[cfg(not(hax))]
impl sealed::Sealed for Journalist {}

#[cfg(not(hax))]
impl RestrictedApi for Journalist {}

/// Journalists: ingredients.
/// Journalists have a signing/verifying key, a reply key,
/// a fetch key, and a collection of one-time signed key bundles
pub struct Journalist {
    signing_key: SigningKeyPair,
    fetch_key: DhFetchKeyPair,
    message_keys: Vec<SignedMessageKeyBundle>,
    /// Long-term SD-APKE key tuple `(sk_J^APKE, pk_J^APKE)`
    reply_apke: MessageKeyPair,
    self_signature: Signature<JournalistLongTermKey>,
    signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    session_storage: SessionStorage,
}

// Public-facing representation of a journalist
// used to send them a message
pub struct JournalistPublicView {
    vk: VerifyingKey,
    fetch_pk: DHPublicKey,
    reply_apke_pk: MessagePublicKey,
    signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    selfsig: Signature<JournalistLongTermKey>,
    kb: SignedKeyBundlePublic,
}

impl JournalistPublicView {
    pub fn new(
        vk: VerifyingKey,
        fetch: DHPublicKey,
        reply_apke: MessagePublicKey,
        selfsig: Signature<JournalistLongTermKey>,
        signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
        kb: SignedKeyBundlePublic,
    ) -> Self {
        Self {
            vk,
            fetch_pk: fetch,
            reply_apke_pk: reply_apke,
            selfsig,
            signed_longterm_key_bytes,
            kb,
        }
    }
}

impl UserPublic for JournalistPublicView {
    fn fetch_pk(&self) -> &DHPublicKey {
        &self.fetch_pk
    }

    fn message_auth_pk(&self) -> &MessagePublicKey {
        &self.reply_apke_pk
    }

    fn message_metadata_pk(&self) -> &MetadataPublicKey {
        &self.kb.0.metadata_pk
    }

    fn message_enc_pk(&self) -> &MessagePublicKey {
        &self.kb.0.apke_pk
    }
}

impl JournalistPublic for JournalistPublicView {
    fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }

    fn self_signature(&self) -> &Signature<JournalistLongTermKey> {
        &self.selfsig
    }

    fn signed_keybytes(&self) -> &SignedLongtermPubKeyBytes {
        &self.signed_longterm_key_bytes
    }

    fn ephemeral_bundle(&self) -> &KeyBundlePublic {
        &self.kb.0
    }

    fn ephemeral_signature(&self) -> &Signature<JournalistEphemeralKey> {
        &self.kb.1
    }
}

impl Client for Journalist {
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.session_storage.nr_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        self.session_storage.nr_key = Some(key);
    }
}

#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
fn keybundle_refs(message_keys: &[SignedMessageKeyBundle]) -> Vec<&MessageKeyBundle> {
    let mut out = Vec::new();
    for signed in message_keys.iter() {
        out.push(&signed.bundle);
    }
    out
}

#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
fn signed_keybundle_publics(message_keys: &[SignedMessageKeyBundle]) -> Vec<SignedKeyBundlePublic> {
    let mut out = Vec::new();
    for signed in message_keys.iter() {
        out.push((signed.bundle.public(), signed.selfsig));
    }
    out
}

/// Private, common to all users, implemented for Journalists
impl UserSecret for Journalist {
    fn num_bundles(&self) -> usize {
        self.message_keys.len()
    }

    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey) {
        (&self.fetch_key.sk, &self.fetch_key.pk)
    }

    fn message_auth_key(&self) -> &crate::message::MessagePrivateKey {
        self.reply_apke.private_key()
    }

    fn own_message_auth_pk(&self) -> &MessagePublicKey {
        self.reply_apke.public_key()
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        // TODO: the journalist doesn't attach their own keys,
        // because the source pulls a fresh set of keys and verifies them
        // in order to reply. either fill with random bytes or use
        // another scheme (fixme)
        Plaintext {
            sender_fetch_key: [0u8; crate::primitives::x25519::DH_PUBLIC_KEY_LEN],
            sender_reply_pubkey_hybrid: [0u8; crate::primitives::xwing::XWING_PUBLIC_KEY_LEN],
            msg: message,
        }
    }

    fn keybundles(&self) -> Vec<&MessageKeyBundle> {
        keybundle_refs(&self.message_keys)
    }
}

impl Enrollable for Journalist {
    fn enroll(&self) -> Enrollment {
        Enrollment {
            bundle: self.signed_longterm_key_bytes.clone(),
            selfsig: self.self_signature,
            keys: (
                self.signing_key.pk,
                self.fetch_key.pk.clone(),
                self.reply_apke.public_key().clone(),
            ),
        }
    }

    fn signed_keybundles(&self) -> Vec<SignedKeyBundlePublic> {
        signed_keybundle_publics(&self.message_keys)
    }

    fn signing_key(&self) -> &VerifyingKey {
        &self.signing_key.pk
    }
}

impl Journalist {
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, num_keybundles: usize) -> Self {
        let mut key_bundles: Vec<SignedMessageKeyBundle> = Vec::with_capacity(num_keybundles);

        let signing_key = SigningKey::new(rng).expect("Signing keygen failed");
        let verifying_key = signing_key.vk;

        let (sk_fetch, pk_fetch) = generate_dh_keypair(rng).expect("DH Keygen (Fetch) failed");

        let reply_apke = message_keygen(rng).expect("SD-APKE Keygen (Reply) failed");

        // Self-sign long-term pubkeys (for enrollment).
        // Covers pk_J^APKE = (pk_J^AKEM, pk_J^PQ) and pk_J^fetch
        let selfsigned_pubkeys =
            SignedLongtermPubKeyBytes::from_keys(reply_apke.public_key(), &pk_fetch);
        let self_signature: Signature<JournalistLongTermKey> =
            signing_key.sign(selfsigned_pubkeys.as_bytes());

        // Generate one-time/short-lived keybundles.
        for _ in 0..num_keybundles {
            let apke_kp = message_keygen(rng).expect("SD-APKE keygen (ephemeral) failed");
            let metadata_kp = metadata_keygen(rng).expect("Failed to generate metadata keys");

            let bundle = MessageKeyBundle::new(apke_kp, metadata_kp);

            let pubkey_bytes = bundle.public().as_bytes();
            let selfsig: Signature<JournalistEphemeralKey> = signing_key.sign(&pubkey_bytes);

            key_bundles.push(SignedMessageKeyBundle { bundle, selfsig });
        }
        assert_eq!(key_bundles.len(), num_keybundles);

        let session_storage = SessionStorage {
            fpf_key: None,
            nr_key: None,
            fpf_signature: None,
        };

        Self {
            signing_key: KeyPair {
                sk: signing_key,
                pk: verifying_key,
            },
            fetch_key: KeyPair {
                sk: sk_fetch,
                pk: pk_fetch,
            },
            reply_apke,
            message_keys: key_bundles,
            self_signature,
            signed_longterm_key_bytes: selfsigned_pubkeys,
            session_storage,
        }
    }

    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn public(&self, idx: usize) -> JournalistPublicView {
        let kb = self.message_keys.get(idx).expect("Bad index");
        JournalistPublicView::new(
            self.signing_key.pk,
            self.fetch_key.pk.clone(),
            self.reply_apke.public_key().clone(),
            self.self_signature,
            self.signed_longterm_key_bytes.clone(),
            (kb.bundle.public(), kb.selfsig),
        )
    }

    /// Extract the long-term keypairs as raw bytes, sufficient to
    /// reconstruct the long-term Journalist state via
    /// [`Journalist::from_long_term_bytes`].
    pub fn long_term_bytes(&self) -> JournalistLongTermBytes {
        JournalistLongTermBytes {
            sig_seed: self.signing_key.sk.as_bytes(),
            fetch_sk: *self.fetch_key.sk.as_bytes(),
            apke_dhakem_sk: *self.reply_apke.private_key().dhakem.as_bytes(),
            apke_mlkem_sk: *self.reply_apke.private_key().mlkem.as_bytes(),
            apke_mlkem_pk: *self.reply_apke.public_key().mlkem.as_bytes(),
        }
    }

    /// Reconstruct the long-term Journalist state from raw key bytes.
    pub fn from_long_term_bytes(parts: JournalistLongTermBytes) -> Self {
        use crate::message::{MessagePrivateKey, MessagePublicKey};
        use crate::primitives::dh_akem::{DhAkemPrivateKey, DhAkemPublicKey};
        use crate::primitives::mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey};
        use crate::primitives::provider;
        use crate::primitives::x25519::{DHPrivateKey, dh_public_key_from_scalar};

        let signing_key = SigningKey::from_seed(parts.sig_seed);
        let verifying_key = signing_key.vk;

        let sk_fetch = DHPrivateKey::from_bytes(parts.fetch_sk);
        let pk_fetch = dh_public_key_from_scalar(parts.fetch_sk);

        let mut apke_dhakem_pk_bytes = [0u8; 32];
        provider::curve25519::secret_to_public(&mut apke_dhakem_pk_bytes, &parts.apke_dhakem_sk);
        let apke_dhakem_sk = DhAkemPrivateKey::from_bytes(parts.apke_dhakem_sk);
        let apke_dhakem_pk = DhAkemPublicKey::from_bytes(apke_dhakem_pk_bytes);
        let apke_mlkem_sk = MLKEM768PrivateKey::from_bytes(parts.apke_mlkem_sk);
        let apke_mlkem_pk = MLKEM768PublicKey::from_bytes(parts.apke_mlkem_pk);

        let reply_apke = MessageKeyPair::new(
            MessagePrivateKey {
                dhakem: apke_dhakem_sk,
                mlkem: apke_mlkem_sk,
            },
            MessagePublicKey {
                dhakem: apke_dhakem_pk,
                mlkem: apke_mlkem_pk,
            },
        );

        let signed_longterm_key_bytes =
            SignedLongtermPubKeyBytes::from_keys(reply_apke.public_key(), &pk_fetch);
        let self_signature: Signature<JournalistLongTermKey> =
            signing_key.sign(signed_longterm_key_bytes.as_bytes());

        Self {
            signing_key: KeyPair {
                sk: signing_key,
                pk: verifying_key,
            },
            fetch_key: KeyPair {
                sk: sk_fetch,
                pk: pk_fetch,
            },
            reply_apke,
            message_keys: Vec::new(),
            self_signature,
            signed_longterm_key_bytes,
            session_storage: SessionStorage {
                fpf_key: None,
                nr_key: None,
                fpf_signature: None,
            },
        }
    }
}

/// Byte representation of a [`Journalist`]'s long-term keypairs, sufficient
/// to reconstruct the long-term state via
/// [`Journalist::from_long_term_bytes`].
pub struct JournalistLongTermBytes {
    pub sig_seed: [u8; 32],
    pub fetch_sk: [u8; 32],
    pub apke_dhakem_sk: [u8; 32],
    pub apke_mlkem_sk: [u8; crate::primitives::mlkem::MLKEM768_PRIVATE_KEY_LEN],
    pub apke_mlkem_pk: [u8; crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Enrollable;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_journalist_setup() {
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let journalist = Journalist::new(&mut rng, 5);
        assert_eq!(journalist.message_keys.len(), 5);
        let skb: Vec<SignedKeyBundlePublic> = journalist.signed_keybundles();
        assert_eq!(journalist.message_keys.len(), skb.len());

        let kbs: Vec<&MessageKeyBundle> = journalist.keybundles();
        assert_eq!(kbs.len(), journalist.message_keys.len());

        for i in 0..kbs.len() {
            assert_eq!(
                journalist.message_keys[i]
                    .bundle
                    .apke
                    .public_key()
                    .as_bytes(),
                kbs[i].apke.public_key().as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i]
                    .bundle
                    .metadata_kp
                    .private_key()
                    .as_bytes(),
                kbs[i].metadata_kp.private_key().as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i]
                    .bundle
                    .metadata_kp
                    .public_key()
                    .as_bytes(),
                kbs[i].metadata_kp.public_key().as_bytes()
            );
        }
    }

    #[test]
    fn test_journalist_enroll_selfsig() {
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let journalist = Journalist::new(&mut rng, 5);
        let e = journalist.enroll();

        journalist
            .signing_key()
            .verify(e.bundle.as_bytes(), &e.selfsig)
            .expect("Need correct enrollment sig");
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_journalist_long_term_bytes_roundtrip(rng_seed: u64) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let original = Journalist::new(&mut rng, 0);
            let parts = original.long_term_bytes();
            let restored = Journalist::from_long_term_bytes(parts);

            // Long-term verifying key and self-signature must match.
            prop_assert_eq!(
                original.signing_key.pk.into_bytes(),
                restored.signing_key.pk.into_bytes()
            );
            prop_assert_eq!(
                original.signed_longterm_key_bytes.as_bytes(),
                restored.signed_longterm_key_bytes.as_bytes()
            );
            prop_assert_eq!(
                original.self_signature.as_bytes(),
                restored.self_signature.as_bytes()
            );
            prop_assert!(restored.message_keys.is_empty());
        }
    }
}
