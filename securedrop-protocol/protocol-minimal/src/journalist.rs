use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::VerifyingKey;
use crate::api::Client;
use crate::ciphertext::Plaintext;
use crate::keys::*;
use crate::message::{
    MessageKeyPair, MessagePrivateKey, MessagePublicKey, keygen as message_keygen,
};
use crate::metadata::{MetadataKeyPair, MetadataPublicKey, keygen as metadata_keygen};
use crate::primitives::dh_akem::{DhAkemPrivateKey, DhAkemPublicKey};
use crate::primitives::mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey};
use crate::primitives::provider;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::generate_dh_keypair;
use crate::sign::{JournalistEphemeralKey, JournalistLongTermKey, Signature, SigningKey};
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

/// Generate one ephemeral key bundle and sign its pubkeys.
fn make_signed_bundle<R: RngCore + CryptoRng>(
    rng: &mut R,
    signing_key: &SigningKey,
) -> SignedMessageKeyBundle {
    let apke_kp = message_keygen(rng).expect("SD-APKE ephemeral keygen failed");
    let metadata_kp = metadata_keygen(rng).expect("Failed to generate metadata keys");

    let bundle = MessageKeyBundle::new(apke_kp, metadata_kp);

    let pubkey_bytes = bundle.public().as_bytes();
    let selfsig: Signature<JournalistEphemeralKey> = signing_key.sign(&pubkey_bytes);

    SignedMessageKeyBundle { bundle, selfsig }
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
            key_bundles.push(make_signed_bundle(rng, &signing_key));
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

    /// Generate `n` fresh signed ephemeral key bundles and retain them in memory.
    ///
    /// The public halves are uploaded to the server via
    /// [`create_ephemeral_key_request`](crate::api::JournalistApi::create_ephemeral_key_request).
    ///
    /// The secret halves should be persisted via [`Journalist::ephemeral_bundle_bytes`].
    pub fn generate_ephemeral_bundles<R: RngCore + CryptoRng>(&mut self, rng: &mut R, n: usize) {
        for _ in 0..n {
            let signed = make_signed_bundle(rng, &self.signing_key.sk);
            self.message_keys.push(signed);
        }
    }

    /// Extract the secret halves of the retained ephemeral key bundles so we can
    /// reconstruct them via [`Journalist::load_ephemeral_bundles`].
    pub fn ephemeral_bundle_bytes(&self) -> Vec<EphemeralBundleBytes> {
        self.message_keys
            .iter()
            .map(|signed| EphemeralBundleBytes::from_bundle(&signed.bundle))
            .collect()
    }

    /// Reconstruct ephemeral key bundles from persisted secret bytes.
    pub fn load_ephemeral_bundles(&mut self, bundles: Vec<EphemeralBundleBytes>) {
        for bytes in bundles {
            let bundle = bytes.into_bundle();
            let pubkey_bytes = bundle.public().as_bytes();
            // Temp: doing this just because we are generating SignedMessageKeyBundle here
            // and we didnt persist the signature
            let selfsig: Signature<JournalistEphemeralKey> =
                self.signing_key.sk.sign(&pubkey_bytes);
            self.message_keys
                .push(SignedMessageKeyBundle { bundle, selfsig });
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

impl JournalistLongTermBytes {
    /// Serialized length of `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk`.
    pub const LEN: usize = 32
        + 32
        + 32
        + crate::primitives::mlkem::MLKEM768_PRIVATE_KEY_LEN
        + crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN;

    /// Serialize as `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.sig_seed);
        out.extend_from_slice(&self.fetch_sk);
        out.extend_from_slice(&self.apke_dhakem_sk);
        out.extend_from_slice(&self.apke_mlkem_sk);
        out.extend_from_slice(&self.apke_mlkem_pk);
        out
    }

    /// Deserialize from `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has the incorrect length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!(
                "Invalid JournalistLongTermBytes length: expected {}, got {}",
                Self::LEN,
                bytes.len()
            ));
        }

        let (sig_seed, rest) = bytes.split_at(32);
        let (fetch_sk, rest) = rest.split_at(32);
        let (apke_dhakem_sk, rest) = rest.split_at(32);
        let (apke_mlkem_sk, apke_mlkem_pk) =
            rest.split_at(crate::primitives::mlkem::MLKEM768_PRIVATE_KEY_LEN);

        // the expects here are fine because the length check above ensures we have the correct length
        Ok(Self {
            sig_seed: sig_seed.try_into().expect("wrong checked length"),
            fetch_sk: fetch_sk.try_into().expect("wrong checked length"),
            apke_dhakem_sk: apke_dhakem_sk.try_into().expect("wrong checked length"),
            apke_mlkem_sk: apke_mlkem_sk.try_into().expect("wrong checked length"),
            apke_mlkem_pk: apke_mlkem_pk.try_into().expect("wrong checked length"),
        })
    }
}

/// Byte representation of one ephemeral key bundle's secret halves
pub struct EphemeralBundleBytes {
    pub apke_dhakem_sk: [u8; 32],
    pub apke_mlkem_sk: [u8; crate::primitives::mlkem::MLKEM768_PRIVATE_KEY_LEN],
    pub apke_mlkem_pk: [u8; crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN],
    pub metadata_sk: [u8; crate::primitives::xwing::XWING_PRIVATE_KEY_LEN],
    pub metadata_pk: [u8; crate::primitives::xwing::XWING_PUBLIC_KEY_LEN],
}

impl EphemeralBundleBytes {
    /// Serialized length of
    /// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk`.
    pub const LEN: usize = 32
        + crate::primitives::mlkem::MLKEM768_PRIVATE_KEY_LEN
        + crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN
        + crate::primitives::xwing::XWING_PRIVATE_KEY_LEN
        + crate::primitives::xwing::XWING_PUBLIC_KEY_LEN;

    fn from_bundle(bundle: &MessageKeyBundle) -> Self {
        Self {
            apke_dhakem_sk: *bundle.apke.private_key().dhakem.as_bytes(),
            apke_mlkem_sk: *bundle.apke.private_key().mlkem.as_bytes(),
            apke_mlkem_pk: *bundle.apke.public_key().mlkem.as_bytes(),
            metadata_sk: *bundle.metadata_kp.secret_bytes(),
            metadata_pk: *bundle.metadata_kp.public_bytes(),
        }
    }

    fn into_bundle(self) -> MessageKeyBundle {
        let mut apke_dhakem_pk_bytes = [0u8; 32];
        provider::curve25519::secret_to_public(&mut apke_dhakem_pk_bytes, &self.apke_dhakem_sk);

        let apke = MessageKeyPair::new(
            MessagePrivateKey {
                dhakem: DhAkemPrivateKey::from_bytes(self.apke_dhakem_sk),
                mlkem: MLKEM768PrivateKey::from_bytes(self.apke_mlkem_sk),
            },
            MessagePublicKey {
                dhakem: DhAkemPublicKey::from_bytes(apke_dhakem_pk_bytes),
                mlkem: MLKEM768PublicKey::from_bytes(self.apke_mlkem_pk),
            },
        );
        let metadata_kp = MetadataKeyPair::from_key_bytes(self.metadata_sk, self.metadata_pk);

        MessageKeyBundle::new(apke, metadata_kp)
    }

    /// Serialize as
    /// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.apke_dhakem_sk);
        out.extend_from_slice(&self.apke_mlkem_sk);
        out.extend_from_slice(&self.apke_mlkem_pk);
        out.extend_from_slice(&self.metadata_sk);
        out.extend_from_slice(&self.metadata_pk);
        out
    }

    /// Deserialize from
    /// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has the incorrect length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!(
                "Invalid EphemeralBundleBytes length: expected {}, got {}",
                Self::LEN,
                bytes.len()
            ));
        }

        let (apke_dhakem_sk, rest) = bytes.split_at(32);
        let (apke_mlkem_sk, rest) =
            rest.split_at(crate::primitives::mlkem::MLKEM768_PRIVATE_KEY_LEN);
        let (apke_mlkem_pk, rest) =
            rest.split_at(crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN);
        let (metadata_sk, metadata_pk) =
            rest.split_at(crate::primitives::xwing::XWING_PRIVATE_KEY_LEN);

        // the expects here are fine bc the length check above ensures we have the correct length
        Ok(Self {
            apke_dhakem_sk: apke_dhakem_sk.try_into().expect("wrong checked length"),
            apke_mlkem_sk: apke_mlkem_sk.try_into().expect("wrong checked length"),
            apke_mlkem_pk: apke_mlkem_pk.try_into().expect("wrong checked length"),
            metadata_sk: metadata_sk.try_into().expect("wrong checked length"),
            metadata_pk: metadata_pk.try_into().expect("wrong checked length"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Enrollable;
    use crate::api::JournalistApi;
    use crate::wire::setup::{JournalistEphemeralKeyRequest, JournalistSetupRequest};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_journalist_setup_request_serde_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let journalist = Journalist::new(&mut rng, 0);
        let req = JournalistSetupRequest {
            enrollment: journalist.enroll(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let restored: JournalistSetupRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            req.enrollment.bundle.as_bytes(),
            restored.enrollment.bundle.as_bytes()
        );
        assert_eq!(
            req.enrollment.selfsig.as_bytes(),
            restored.enrollment.selfsig.as_bytes()
        );
        assert_eq!(
            req.enrollment.keys.0.into_bytes(),
            restored.enrollment.keys.0.into_bytes()
        );
        assert_eq!(
            req.enrollment.keys.1.into_bytes(),
            restored.enrollment.keys.1.into_bytes()
        );
        assert_eq!(
            req.enrollment.keys.2.as_bytes(),
            restored.enrollment.keys.2.as_bytes()
        );
    }

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

        #[test]
        fn test_journalist_long_term_bytes_serde_roundtrip(rng_seed: u64) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let parts = Journalist::new(&mut rng, 0).long_term_bytes();

            let bytes = parts.as_bytes();
            prop_assert_eq!(bytes.len(), JournalistLongTermBytes::LEN);

            let restored = JournalistLongTermBytes::from_bytes(&bytes).expect("valid length");
            prop_assert_eq!(restored.sig_seed, parts.sig_seed);
            prop_assert_eq!(restored.fetch_sk, parts.fetch_sk);
            prop_assert_eq!(restored.apke_dhakem_sk, parts.apke_dhakem_sk);
            prop_assert_eq!(restored.apke_mlkem_sk, parts.apke_mlkem_sk);
            prop_assert_eq!(restored.apke_mlkem_pk, parts.apke_mlkem_pk);
        }

        #[test]
        fn test_ephemeral_bundle_bytes_roundtrip(rng_seed: u64, n in 0usize..4) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let mut original = Journalist::new(&mut rng, 0);
            original.generate_ephemeral_bundles(&mut rng, n);

            let persisted: Vec<EphemeralBundleBytes> = original
                .ephemeral_bundle_bytes()
                .into_iter()
                .map(|b| {
                    let bytes = b.as_bytes();
                    prop_assert_eq!(bytes.len(), EphemeralBundleBytes::LEN);
                    Ok(EphemeralBundleBytes::from_bytes(&bytes).expect("valid length"))
                })
                .collect::<Result<_, TestCaseError>>()?;

            let mut restored = Journalist::from_long_term_bytes(original.long_term_bytes());
            restored.load_ephemeral_bundles(persisted);

            let orig_pub = original.signed_keybundles();
            let restored_pub = restored.signed_keybundles();
            prop_assert_eq!(orig_pub.len(), n);
            prop_assert_eq!(restored_pub.len(), n);
            for (a, b) in orig_pub.iter().zip(restored_pub.iter()) {
                prop_assert_eq!(a.0.as_bytes(), b.0.as_bytes());
                prop_assert_eq!(a.1.as_bytes(), b.1.as_bytes());
            }
        }

        #[test]
        fn test_journalist_ephemeral_key_request_serde_roundtrip(rng_seed: u64, n in 1usize..4) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let mut journalist = Journalist::new(&mut rng, 0);
            journalist.generate_ephemeral_bundles(&mut rng, n);

            let req = journalist.create_ephemeral_key_request();
            let json = serde_json::to_string(&req).expect("serialize");
            let restored: JournalistEphemeralKeyRequest =
                serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(
                req.verifying_key.into_bytes(),
                restored.verifying_key.into_bytes()
            );
            prop_assert_eq!(req.bundles.len(), n);
            prop_assert_eq!(restored.bundles.len(), n);
            for (a, b) in req.bundles.iter().zip(restored.bundles.iter()) {
                prop_assert_eq!(a.0.as_bytes(), b.0.as_bytes());
                prop_assert_eq!(a.1.as_bytes(), b.1.as_bytes());
            }
        }
    }

    #[test]
    fn test_journalist_long_term_bytes_from_bytes_rejects_wrong_length() {
        assert!(JournalistLongTermBytes::from_bytes(&[]).is_err());
        assert!(
            JournalistLongTermBytes::from_bytes(&[0u8; JournalistLongTermBytes::LEN - 1]).is_err()
        );
        assert!(
            JournalistLongTermBytes::from_bytes(&[0u8; JournalistLongTermBytes::LEN + 1]).is_err()
        );
    }
}
