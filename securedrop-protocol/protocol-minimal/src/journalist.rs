use crate::VerifyingKey;
use crate::api::Api;
use crate::api::JournalistApi;
use crate::api::restricted;
use crate::primitives::dh_akem::DhAkemPrivateKey;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::dh_akem::generate_dh_akem_keypair;
use crate::primitives::mlkem::MLKEM768PublicKey;
use crate::primitives::mlkem::generate_mlkem768_keypair;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::generate_dh_keypair;
use crate::primitives::xwing::XWingPublicKey;
use crate::primitives::xwing::generate_xwing_keypair;
use crate::sign::{JournalistEphemeralKey, JournalistLongTermKey, Signature, SigningKey};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::ciphertext::Plaintext;
use crate::constants::*;
use crate::keys::*;
use crate::traits::private;
use crate::traits::{Enrollable, JournalistPublic, UserPublic, UserSecret};

/// Journalists: ingredients.
/// Journalists have a signing/verifying key, a reply key,
/// a fetch key, and a collection of one-time signed key bundles
pub struct Journalist {
    signing_key: SigningKeyPair,
    fetch_key: DhFetchKeyPair,
    message_keys: Vec<SignedMessageKeyBundle>,
    reply_key: DhAkemKeyPair,
    self_signature: Signature<JournalistLongTermKey>,
    signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    session_storage: SessionStorage,
}

// Public-facing representation of a journalist
// used to send them a message
pub struct JournalistPublicView {
    vk: VerifyingKey,
    fetch_pk: DHPublicKey,
    dhakem_pk_reply: DhAkemPublicKey,
    signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
    selfsig: Signature<JournalistLongTermKey>,
    kb: SignedKeyBundlePublic,
}

impl JournalistPublicView {
    pub fn new(
        vk: VerifyingKey,
        fetch: DHPublicKey,
        dhakem: DhAkemPublicKey,
        selfsig: Signature<JournalistLongTermKey>,
        signed_longterm_key_bytes: SignedLongtermPubKeyBytes,
        kb: SignedKeyBundlePublic,
    ) -> Self {
        Self {
            vk,
            fetch_pk: fetch,
            dhakem_pk_reply: dhakem,
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

    fn message_auth_pk(&self) -> &DhAkemPublicKey {
        &self.dhakem_pk_reply
    }

    fn message_psk_pk(&self) -> &MLKEM768PublicKey {
        &self.kb.0.mlkem_pk
    }

    fn message_metadata_pk(&self) -> &XWingPublicKey {
        &self.kb.0.xwing_pk
    }

    fn message_enc_pk(&self) -> &DhAkemPublicKey {
        &self.kb.0.dhakem_pk
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

impl Api for Journalist {
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.session_storage.nr_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        self.session_storage.nr_key = Some(key);
    }
}

impl restricted::RestrictedApi for Journalist {}
impl JournalistApi for Journalist {}

impl private::Sealed for Journalist {}
/// Private, common to all users, implemented for Journalists
impl UserSecret for Journalist {
    fn num_bundles(&self) -> usize {
        self.message_keys.len()
    }

    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey) {
        (&self.fetch_key.sk, &self.fetch_key.pk)
    }

    fn message_auth_keypair(&self) -> (&DhAkemPrivateKey, &DhAkemPublicKey) {
        // "reply key" (long term dh-akem key)
        (&self.reply_key.sk, &self.reply_key.pk)
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        // TODO: the journalist doesn't attach their own keys,
        // because the source pulls a fresh set of keys and verifies them
        // in order to reply. either fill with random bytes or use
        // another scheme (fixme)
        Plaintext {
            sender_reply_pubkey_pq_psk: [0u8; LEN_MLKEM_ENCAPS_KEY],
            sender_fetch_key: [0u8; LEN_DH_ITEM],
            sender_reply_pubkey_hybrid: [0u8; LEN_XWING_ENCAPS_KEY],
            msg: message,
        }
    }

    fn keybundles(&self) -> impl Iterator<Item = &MessageKeyBundle> {
        self.message_keys.iter().map(|signed| &signed.bundle)
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
                self.reply_key.pk.clone(),
            ),
        }
    }

    fn signed_keybundles(&self) -> impl Iterator<Item = SignedKeyBundlePublic> {
        self.message_keys
            .iter()
            .map(|k| (k.bundle.public(), k.selfsig))
    }

    fn signing_key(&self) -> &VerifyingKey {
        &self.signing_key.pk
    }
}

impl Journalist {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, num_keybundles: usize) -> Self {
        let mut key_bundles: Vec<SignedMessageKeyBundle> = Vec::with_capacity(num_keybundles);

        let signing_key = SigningKey::new(&mut *rng).expect("Signing keygen failed");
        let verifying_key = signing_key.vk;

        let (sk_fetch, pk_fetch) =
            generate_dh_keypair(&mut *rng).expect("DH Keygen (Fetch) failed");

        let (sk_reply, pk_reply) =
            generate_dh_akem_keypair(&mut *rng).expect("DH-AKEM Keygen (Reply) failed");

        // Self-sign long-term pubkeys (for enrollment).
        let selfsigned_pubkeys = SignedLongtermPubKeyBytes::from_keys(&pk_fetch, &pk_reply);
        let self_signature: Signature<JournalistLongTermKey> =
            signing_key.sign(selfsigned_pubkeys.as_bytes());

        // Generate one-time/short-lived keybundles.
        for _ in 0..num_keybundles {
            let (sk_dh, pk_dh) = generate_dh_akem_keypair(rng).expect("DH keygen (DH-AKEM) failed");

            let (sk_pqkem_psk, pk_pqkem_psk) =
                generate_mlkem768_keypair(rng).expect("Failed to generate ml-kem keys!");

            let (sk_md, pk_md) =
                generate_xwing_keypair(rng).expect("Failed to generate xwing keys");

            let bundle = MessageKeyBundle::new(
                KeyPair {
                    sk: sk_dh,
                    pk: pk_dh,
                },
                KeyPair {
                    sk: sk_pqkem_psk,
                    pk: pk_pqkem_psk,
                },
                KeyPair {
                    sk: sk_md,
                    pk: pk_md,
                },
            );

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
            reply_key: KeyPair {
                sk: sk_reply,
                pk: pk_reply,
            },
            message_keys: key_bundles,
            self_signature,
            signed_longterm_key_bytes: selfsigned_pubkeys,
            session_storage,
        }
    }

    pub fn public(&self, idx: usize) -> JournalistPublicView {
        let kb = self.message_keys.get(idx).expect("Bad index");
        JournalistPublicView::new(
            self.signing_key.pk,
            self.fetch_key.pk.clone(),
            self.reply_key.pk.clone(),
            self.self_signature,
            self.signed_longterm_key_bytes.clone(),
            (kb.bundle.public(), kb.selfsig),
        )
    }
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
        let skb: Vec<SignedKeyBundlePublic> = journalist.signed_keybundles().collect();
        assert_eq!(journalist.message_keys.len(), skb.len());

        let kbs: Vec<&MessageKeyBundle> = journalist.keybundles().collect();
        assert_eq!(kbs.len(), journalist.message_keys.len());

        for i in 0..kbs.len() {
            assert_eq!(
                journalist.message_keys[i].bundle.dh_akem.sk.as_bytes(),
                kbs[i].dh_akem.sk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.dh_akem.pk.as_bytes(),
                kbs[i].dh_akem.pk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.mlkem.sk.as_bytes(),
                kbs[i].mlkem.sk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.mlkem.pk.as_bytes(),
                kbs[i].mlkem.pk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.xwing_md.sk.as_bytes(),
                kbs[i].xwing_md.sk.as_bytes()
            );
            assert_eq!(
                journalist.message_keys[i].bundle.xwing_md.pk.as_bytes(),
                kbs[i].xwing_md.pk.as_bytes()
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
}
