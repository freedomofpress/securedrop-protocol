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
use crate::primitives::ristretto255::{DHPrivateKey, DHPublicKey, generate_dh_keypair};
use crate::primitives::xwing::{XWingPrivateKey, XWingPublicKey};
use crate::sign::{JournalistLongTermKey, JournalistShortTermKey, Signature, SigningKey};
use crate::traits::{Enrollable, JournalistPublic, RestrictedApi, UserPublic, UserSecret};

// caution: do not re-export!
use crate::sealed;

#[cfg(not(hax))]
impl sealed::Sealed for Journalist {}

#[cfg(not(hax))]
impl RestrictedApi for Journalist {}

/// Journalists: ingredients.
/// Journalists have a signing/verifying key, a reply key,
/// a fetch key, and a collection of short-lived signed key bundles
pub struct Journalist {
    signing_key: SigningKeyPair,
    fetch_key: DhFetchKeyPair,
    message_keys: Vec<SignedMessageKeyBundle>,
    /// Long-term SD-APKE key tuple `(sk_J^APKE, pk_J^APKE)`
    reply_apke: MessageKeyPair,
    signed_longterm_key_bundle: SignedLongtermKeyBundle,
    session_storage: SessionStorage,
}

// Public-facing representation of a journalist
// used to send them a message
#[cfg_attr(not(hax), derive(serde::Serialize, serde::Deserialize))]
pub struct JournalistPublicView {
    vk: VerifyingKey,
    signed_longterm_key_bundle: SignedLongtermKeyBundle,
    kb: SignedKeyBundlePublic,
}

impl JournalistPublicView {
    pub fn new(
        vk: VerifyingKey,
        signed_longterm_key_bundle: SignedLongtermKeyBundle,
        kb: SignedKeyBundlePublic,
    ) -> Self {
        Self {
            vk,
            signed_longterm_key_bundle,
            kb,
        }
    }
}

impl UserPublic for JournalistPublicView {
    fn fetch_pk(&self) -> &DHPublicKey {
        &self.signed_longterm_key_bundle.bundle.fetch_pk
    }

    fn message_auth_pk(&self) -> &MessagePublicKey {
        &self.signed_longterm_key_bundle.bundle.apke
    }

    fn message_metadata_pk(&self) -> &MetadataPublicKey {
        &self.kb.bundle.metadata_pk
    }

    fn message_enc_pk(&self) -> &MessagePublicKey {
        &self.kb.bundle.apke_pk
    }
}

impl JournalistPublic for JournalistPublicView {
    fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }

    fn self_signature(&self) -> &Signature<JournalistLongTermKey> {
        &self.signed_longterm_key_bundle.selfsig
    }

    fn signed_keybytes(&self) -> &SignedLongtermKeyBundle {
        &self.signed_longterm_key_bundle
    }

    fn short_term_bundle(&self) -> &KeyBundlePublic {
        &self.kb.bundle
    }

    fn short_term_signature(&self) -> &Signature<JournalistShortTermKey> {
        &self.kb.selfsig
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
        out.push(SignedKeyBundlePublic::new(signed.bundle.public(), signed.epoch, signed.selfsig));
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

    fn message_auth_keypair(&self) -> &MessageKeyPair {
        &self.reply_apke
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        // TODO: the journalist doesn't attach their own keys,
        // because the source pulls a fresh set of keys and verifies them
        // in order to reply. either fill with random bytes or use
        // another scheme (fixme)
        Plaintext {
            sender_fetch_key: crate::primitives::ristretto255::placeholder_public_key(),
            sender_reply_pubkey_hybrid: [0u8; XWingPublicKey::LEN],
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
            bundle: self.signed_longterm_key_bundle.clone(),
            verification_key: self.signing_key.pk,
        }
    }

    fn signed_keybundles(&self) -> Vec<SignedKeyBundlePublic> {
        signed_keybundle_publics(&self.message_keys)
    }

    fn signing_key(&self) -> &VerifyingKey {
        &self.signing_key.pk
    }
}

/// Generate one short-term key bundle for `epoch` and sign its pubkey and epoch
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
fn make_signed_bundle<R: RngCore + CryptoRng>(
    rng: &mut R,
    signing_key: &SigningKey,
    epoch: Epoch,
) -> SignedMessageKeyBundle {
    let apke_kp = message_keygen(rng).expect("SD-APKE short term keygen failed");
    let metadata_kp = metadata_keygen(rng).expect("Failed to generate metadata keys");

    let bundle = MessageKeyBundle::new(apke_kp, metadata_kp);

    let pubkey_bytes = SignedKeyBundlePublic::make_signed_bytes(&bundle.public(), epoch);
    let selfsig: Signature<JournalistShortTermKey> = signing_key.sign(&pubkey_bytes);

    SignedMessageKeyBundle {
        bundle,
        epoch,
        selfsig,
    }
}

impl Journalist {
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, num_keybundles: usize, epoch: Epoch) -> Self {
        let mut key_bundles: Vec<SignedMessageKeyBundle> = Vec::with_capacity(num_keybundles);

        let signing_key = SigningKey::new(rng).expect("Signing keygen failed");
        let verifying_key = signing_key.vk;

        let (sk_fetch, pk_fetch) = generate_dh_keypair(rng);

        let reply_apke = message_keygen(rng).expect("SD-APKE Keygen (Reply) failed");

        // Self-sign long-term pubkeys (for enrollment).
        // Covers pk_J^APKE = (pk_J^AKEM, pk_J^PQ) and pk_J^fetch
        let longterm_bundle = LongtermKeyBundle::new(reply_apke.public_key().clone(), pk_fetch);
        let self_signature: Signature<JournalistLongTermKey> =
            signing_key.sign(&longterm_bundle.as_bytes());
        let selfsigned_pubkeys = SignedLongtermKeyBundle::new(longterm_bundle, self_signature);

        // Generate short-term keybundles for `epoch`.
        for _ in 0..num_keybundles {
            key_bundles.push(make_signed_bundle(rng, &signing_key, epoch));
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
            signed_longterm_key_bundle: selfsigned_pubkeys,
            session_storage,
        }
    }

    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn public(&self, idx: usize) -> JournalistPublicView {
        let kb = self.message_keys.get(idx).expect("Bad index");
        JournalistPublicView::new(
            self.signing_key.pk,
            self.signed_longterm_key_bundle.clone(),
            SignedKeyBundlePublic::new(kb.bundle.public(), kb.epoch, kb.selfsig),
        )
    }

    /// Extract the long-term keypairs as raw bytes, sufficient to
    /// reconstruct the long-term Journalist state via
    /// [`Journalist::from_long_term_bytes`].
    pub fn long_term_bytes(&self) -> JournalistLongTermBytes {
        JournalistLongTermBytes {
            sig_seed: self.signing_key.sk.as_bytes(),
            fetch_sk: self.fetch_key.sk.to_bytes(),
            apke_dhakem_sk: *self.reply_apke.private_key().dhakem.as_bytes(),
            apke_mlkem_sk: *self.reply_apke.private_key().mlkem.as_bytes(),
            apke_mlkem_pk: *self.reply_apke.public_key().mlkem.as_bytes(),
        }
    }

    /// Reconstruct the long-term Journalist state from raw key bytes.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn from_long_term_bytes(parts: JournalistLongTermBytes) -> Result<Self, anyhow::Error> {
        use crate::message::{MessagePrivateKey, MessagePublicKey};
        use crate::primitives::dh_akem::{DhAkemPrivateKey, DhAkemPublicKey};
        use crate::primitives::mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey};
        use crate::primitives::provider;

        let signing_key = SigningKey::from_seed(parts.sig_seed);
        let verifying_key = signing_key.vk;
        let sk_fetch = DHPrivateKey::decode(parts.fetch_sk)?;
        let pk_fetch = sk_fetch.public_key();

        let mut apke_dhakem_pk_bytes = [0u8; DhAkemPublicKey::LEN];
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

        let longterm_bundle = LongtermKeyBundle::new(reply_apke.public_key().clone(), pk_fetch);
        let self_signature: Signature<JournalistLongTermKey> =
            signing_key.sign(&longterm_bundle.as_bytes());
        let signed_longterm_key_bundle =
            SignedLongtermKeyBundle::new(longterm_bundle, self_signature);

        Ok(Self {
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
            signed_longterm_key_bundle,
            session_storage: SessionStorage {
                fpf_key: None,
                nr_key: None,
                fpf_signature: None,
            },
        })
    }

    /// Generate `n` fresh signed short-term key bundles for `epoch` and retain them in memory.
    ///
    /// The public halves are uploaded to the server via
    /// [`create_short_term_key_request`](crate::api::JournalistApi::create_short_term_key_request).
    ///
    /// The secret halves should be persisted via [`Journalist::short_term_bundle_bytes`].
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn generate_short_term_bundles<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        n: usize,
        epoch: Epoch,
    ) {
        for _ in 0..n {
            let signed = make_signed_bundle(rng, &self.signing_key.sk, epoch);
            self.message_keys.push(signed);
        }
    }

    /// Extract the secret halves of the retained short term key bundles so we can
    /// reconstruct them via [`Journalist::load_short_term_bundles`].
    ///
    /// Used by the demo.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn short_term_bundle_bytes(&self) -> Vec<ShortTermBundleBytes> {
        self.message_keys
            .iter()
            .map(|signed| ShortTermBundleBytes::from_bundle(&signed.bundle, signed.epoch))
            .collect()
    }

    /// Reconstruct short term key bundles from persisted secret bytes.
    ///
    /// Used by the demo
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn load_short_term_bundles(&mut self, bundles: Vec<ShortTermBundleBytes>) {
        for bytes in bundles {
            let epoch = bytes.epoch();
            let bundle = bytes.into_bundle();
            let pubkey_bytes = SignedKeyBundlePublic::make_signed_bytes(&bundle.public(), epoch);
            // Temp: doing this just because we are generating SignedMessageKeyBundle here
            // and we didnt persist the signature
            let selfsig: Signature<JournalistShortTermKey> =
                self.signing_key.sk.sign(&pubkey_bytes);
            self.message_keys.push(SignedMessageKeyBundle {
                bundle,
                epoch,
                selfsig,
            });
        }
    }
}

/// Byte representation of a [`Journalist`]'s long-term keypairs, sufficient
/// to reconstruct the long-term state via
/// [`Journalist::from_long_term_bytes`].
pub struct JournalistLongTermBytes {
    pub sig_seed: [u8; SigningKey::SEED_LEN],
    pub fetch_sk: [u8; DHPrivateKey::LEN],
    pub apke_dhakem_sk: [u8; DhAkemPrivateKey::LEN],
    pub apke_mlkem_sk: [u8; MLKEM768PrivateKey::LEN],
    pub apke_mlkem_pk: [u8; MLKEM768PublicKey::LEN],
}

impl JournalistLongTermBytes {
    /// Serialized length of `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk`.
    pub const LEN: usize = SigningKey::SEED_LEN
        + DHPrivateKey::LEN
        + DhAkemPrivateKey::LEN
        + MLKEM768PrivateKey::LEN
        + MLKEM768PublicKey::LEN;

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

        let (sig_seed, rest) = bytes.split_at(SigningKey::SEED_LEN);
        let (fetch_sk, rest) = rest.split_at(DHPrivateKey::LEN);
        let (apke_dhakem_sk, rest) = rest.split_at(DhAkemPrivateKey::LEN);
        let (apke_mlkem_sk, apke_mlkem_pk) = rest.split_at(MLKEM768PrivateKey::LEN);

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

/// Byte representation of one short-term key bundle's secret halves and key epoch
pub struct ShortTermBundleBytes {
    pub apke_dhakem_sk: [u8; DhAkemPrivateKey::LEN],
    pub apke_mlkem_sk: [u8; MLKEM768PrivateKey::LEN],
    pub apke_mlkem_pk: [u8; MLKEM768PublicKey::LEN],
    pub metadata_sk: [u8; XWingPrivateKey::LEN],
    pub metadata_pk: [u8; XWingPublicKey::LEN],
    pub epoch: [u8; Epoch::ENCODED_LEN],
}

impl ShortTermBundleBytes {
    /// Serialized length of
    /// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk`.
    pub const LEN: usize = DhAkemPrivateKey::LEN
        + MLKEM768PrivateKey::LEN
        + MLKEM768PublicKey::LEN
        + XWingPrivateKey::LEN
        + XWingPublicKey::LEN
        + Epoch::ENCODED_LEN;

    fn from_bundle(bundle: &MessageKeyBundle, epoch: Epoch) -> Self {
        Self {
            apke_dhakem_sk: *bundle.apke.private_key().dhakem.as_bytes(),
            apke_mlkem_sk: *bundle.apke.private_key().mlkem.as_bytes(),
            apke_mlkem_pk: *bundle.apke.public_key().mlkem.as_bytes(),
            metadata_sk: *bundle.metadata_kp.secret_bytes(),
            metadata_pk: *bundle.metadata_kp.public_bytes(),
            epoch: epoch.as_bytes(),
        }
    }

    #[cfg_attr(hax, hax_lib::opaque)]
    fn into_bundle(self) -> MessageKeyBundle {
        let mut apke_dhakem_pk_bytes = [0u8; DhAkemPublicKey::LEN];
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

    /// Get the epoch of this short-term bundle.
    pub fn epoch(&self) -> Epoch {
        Epoch::from_bytes(self.epoch)
    }

    /// Serialize as
    /// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk || epoch`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.apke_dhakem_sk);
        out.extend_from_slice(&self.apke_mlkem_sk);
        out.extend_from_slice(&self.apke_mlkem_pk);
        out.extend_from_slice(&self.metadata_sk);
        out.extend_from_slice(&self.metadata_pk);
        out.extend_from_slice(&self.epoch);
        out
    }

    /// Deserialize from
    /// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk || epoch` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has the incorrect length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != Self::LEN {
            return Err(anyhow::anyhow!(
                "Invalid ShortTermBundleBytes length: expected {}, got {}",
                Self::LEN,
                bytes.len()
            ));
        }

        let (apke_dhakem_sk, rest) = bytes.split_at(DhAkemPrivateKey::LEN);
        let (apke_mlkem_sk, rest) = rest.split_at(MLKEM768PrivateKey::LEN);
        let (apke_mlkem_pk, rest) = rest.split_at(MLKEM768PublicKey::LEN);
        let (metadata_sk, rest) = rest.split_at(XWingPrivateKey::LEN);
        let (metadata_pk, epoch) = rest.split_at(XWingPublicKey::LEN);

        // the expects here are fine bc the length check above ensures we have the correct length
        Ok(Self {
            apke_dhakem_sk: apke_dhakem_sk.try_into().expect("wrong checked length"),
            apke_mlkem_sk: apke_mlkem_sk.try_into().expect("wrong checked length"),
            apke_mlkem_pk: apke_mlkem_pk.try_into().expect("wrong checked length"),
            metadata_sk: metadata_sk.try_into().expect("wrong checked length"),
            metadata_pk: metadata_pk.try_into().expect("wrong checked length"),
            epoch: epoch.try_into().expect("wrong checked length"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Enrollable;
    use crate::api::JournalistApi;
    use crate::wire::setup::{JournalistSetupRequest, JournalistShortTermKeyRequest};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    // Test epoch index
    const TEST_EPOCH: Epoch = Epoch(11);

    #[test]
    fn test_journalist_setup_request_serde_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let journalist = Journalist::new(&mut rng, 0, TEST_EPOCH);
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
            req.enrollment.bundle.selfsig.as_bytes(),
            restored.enrollment.bundle.selfsig.as_bytes()
        );
        assert_eq!(
            req.enrollment.verification_key.into_bytes(),
            restored.enrollment.verification_key.into_bytes()
        );
    }

    #[test]
    fn test_journalist_setup() {
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let journalist = Journalist::new(&mut rng, 5, TEST_EPOCH);
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

        let journalist = Journalist::new(&mut rng, 5, TEST_EPOCH);
        let e = journalist.enroll();

        journalist
            .signing_key()
            .verify(&e.bundle.bundle_bytes(), &e.bundle.selfsig)
            .expect("Need correct enrollment sig");
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_journalist_long_term_bytes_roundtrip(rng_seed: u64) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let original = Journalist::new(&mut rng, 0, TEST_EPOCH);
            let parts = original.long_term_bytes();
            let restored =
                Journalist::from_long_term_bytes(parts).expect("valid long-term bytes");

            // Long-term verifying key and self-signature must match.
            prop_assert_eq!(
                original.signing_key.pk.into_bytes(),
                restored.signing_key.pk.into_bytes()
            );
            prop_assert_eq!(
                original.signed_longterm_key_bundle.as_bytes(),
                restored.signed_longterm_key_bundle.as_bytes()
            );
            prop_assert!(restored.message_keys.is_empty());
        }

        #[test]
        fn test_journalist_long_term_bytes_serde_roundtrip(rng_seed: u64) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let parts = Journalist::new(&mut rng, 0, TEST_EPOCH).long_term_bytes();

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
        fn test_short_term_bundle_bytes_roundtrip(rng_seed: u64, n in 0usize..4) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let mut original = Journalist::new(&mut rng, 0, TEST_EPOCH);
            original.generate_short_term_bundles(&mut rng, n, TEST_EPOCH);

            let persisted: Vec<ShortTermBundleBytes> = original
                .short_term_bundle_bytes()
                .into_iter()
                .map(|b| {
                    let bytes = b.as_bytes();
                    prop_assert_eq!(bytes.len(), ShortTermBundleBytes::LEN);
                    Ok(ShortTermBundleBytes::from_bytes(&bytes).expect("valid length"))
                })
                .collect::<Result<_, TestCaseError>>()?;

            let mut restored = Journalist::from_long_term_bytes(original.long_term_bytes())
                .expect("valid long-term bytes");
            restored.load_short_term_bundles(persisted);

            let orig_pub = original.signed_keybundles();
            let restored_pub = restored.signed_keybundles();
            prop_assert_eq!(orig_pub.len(), n);
            prop_assert_eq!(restored_pub.len(), n);
            for (a, b) in orig_pub.iter().zip(restored_pub.iter()) {
                prop_assert_eq!(b.epoch, TEST_EPOCH);
                prop_assert_eq!(a.bundle.as_bytes(), b.bundle.as_bytes());
                prop_assert_eq!(a.signed_bytes(), b.signed_bytes());
                prop_assert_eq!(a.selfsig.as_bytes(), b.selfsig.as_bytes());
            }
        }

        #[test]
        fn test_journalist_short_term_key_request_serde_roundtrip(rng_seed: u64, n in 1usize..4) {
            let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
            let mut journalist = Journalist::new(&mut rng, 0, TEST_EPOCH);
            journalist.generate_short_term_bundles(&mut rng, n, TEST_EPOCH);

            let req = journalist.create_short_term_key_request();
            let json = serde_json::to_string(&req).expect("serialize");
            let restored: JournalistShortTermKeyRequest =
                serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(
                req.verifying_key.into_bytes(),
                restored.verifying_key.into_bytes()
            );
            prop_assert_eq!(req.bundles.len(), n);
            prop_assert_eq!(restored.bundles.len(), n);
            for (a, b) in req.bundles.iter().zip(restored.bundles.iter()) {
                prop_assert_eq!(a.bundle.as_bytes(), b.bundle.as_bytes());
                                prop_assert_eq!(a.epoch.as_bytes(), b.epoch.as_bytes());
                prop_assert_eq!(a.selfsig.as_bytes(), b.selfsig.as_bytes());
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
