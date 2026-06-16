use crate::VerifyingKey;
use crate::api::Client;
use crate::message::{MessagePublicKey, deterministic_keygen as kgen_deterministic_message};
use crate::metadata::{MetadataPublicKey, deterministic_keygen as kgen_deterministic_metadata};
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::deterministic_dh_keygen;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::Error;
use bip39::{Language, Mnemonic};
use rand_core::{CryptoRng, RngCore};

use crate::ciphertext::Plaintext;
use crate::keys::*;
use crate::primitives::provider::hkdf;
use crate::primitives::x25519::DH_PUBLIC_KEY_LEN;
use crate::primitives::xwing::XWING_PUBLIC_KEY_LEN;
use crate::traits::{UserPublic, UserSecret};

// do not re-export!
use crate::sealed;
impl sealed::Sealed for Source {}

/// Fixed, public, application-specific salt for source key derivation.
const SOURCE_KDF_SALT: &[u8] = b"securedrop-source-v1";

/// A source and their long-term key material (step 4).
///
/// A source's keys are fully determined by their passphrase, a 12-word BIP39
/// mnemonic. The mnemonic's 16-byte entropy is used directly as the master key
/// `mk`, from which the fetch key, APKE key, and PKE key are derived with a
/// domain-separated KDF. Returning sources reconstruct the same keys by calling
/// [`Source::from_passphrase`] with the same mnemonic.
pub struct Source {
    fetch_key: DhFetchKeyPair,
    message_keys: MessageKeyBundle,
    passphrase: String,
    session: SessionStorage,
}

impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Using non-exhaustive to avoid leaking source keys.
        f.debug_struct("Source").finish_non_exhaustive()
    }
}

/// The public key material of a source, used by journalists to send replies.
#[derive(Debug, Clone)]
pub struct SourcePublicView {
    fetch_pk: DHPublicKey,
    apke_pk: MessagePublicKey,
    message_pks: KeyBundlePublic,
}

impl UserPublic for SourcePublicView {
    fn fetch_pk(&self) -> &DHPublicKey {
        &self.fetch_pk
    }

    fn message_auth_pk(&self) -> &MessagePublicKey {
        &self.apke_pk
    }

    fn message_metadata_pk(&self) -> &MetadataPublicKey {
        &self.message_pks.metadata_pk
    }

    fn message_enc_pk(&self) -> &MessagePublicKey {
        &self.message_pks.apke_pk
    }
}

impl Client for Source {
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.session.nr_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        self.session.nr_key = Some(key);
    }
}

/// Private, common to all users, implemented for sources
impl UserSecret for Source {
    fn num_bundles(&self) -> usize {
        1
    }

    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey) {
        (&self.fetch_key.sk, &self.fetch_key.pk)
    }

    fn message_auth_key(&self) -> &crate::message::MessagePrivateKey {
        self.message_keys.apke.private_key()
    }

    fn message_auth_pk(&self) -> &crate::message::MessagePublicKey {
        self.message_keys.apke.public_key()
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        let mut fetch_pk = [0u8; DH_PUBLIC_KEY_LEN];
        fetch_pk.copy_from_slice(&self.fetch_key.pk.into_bytes());

        let mut reply_key_pq_hybrid = [0u8; XWING_PUBLIC_KEY_LEN];
        reply_key_pq_hybrid.copy_from_slice(self.message_keys.metadata_kp.public_key().as_bytes());

        Plaintext {
            sender_fetch_key: fetch_pk,
            sender_reply_pubkey_hybrid: reply_key_pq_hybrid,
            msg: message,
        }
    }

    fn keybundles(&self) -> Vec<&MessageKeyBundle> {
        alloc::vec![&self.message_keys]
    }
}

impl Source {
    /// Create a new source with a randomly generated 12-word BIP39 mnemonic.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("16 bytes is valid BIP39 entropy");
        Self::from_master_key(&entropy, mnemonic.to_string())
    }

    /// Returns the source's passphrase as a 12-word BIP39 mnemonic.
    ///
    /// # Security
    ///
    /// The passphrase is the root secret from which all source keys are
    /// derived. It MUST be stored and transmitted only over secure channels.
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Reconstruct source keys from a 12-word BIP39 mnemonic (step 4).
    ///
    /// # Errors
    ///
    /// Returns an error if `passphrase` is not a valid 12-word BIP39 mnemonic,
    /// i.e. it contains an unknown word, has the wrong length, or fails the
    /// checksum.
    pub fn from_passphrase(passphrase: &str) -> Result<Self, Error> {
        let mnemonic = Mnemonic::parse_in(Language::English, passphrase)
            .map_err(|e| anyhow::anyhow!("invalid BIP39 mnemonic: {e}"))?;

        let (entropy, len) = mnemonic.to_entropy_array();
        if len != 16 {
            return Err(anyhow::anyhow!(
                "source passphrase must be a 12-word BIP39 mnemonic (128-bit entropy)"
            ));
        }
        let mut mk = [0u8; 16];
        mk.copy_from_slice(&entropy[..16]);

        Ok(Self::from_master_key(&mk, mnemonic.to_string()))
    }

    /// Derive a source's long-term keys from the master key `mk` (the 16-byte
    /// BIP39 entropy), then assemble the [`Source`] tagged with the originating
    /// `passphrase` mnemonic.
    ///
    /// Each private key is derived from `mk` with a domain-separated KDF.
    fn from_master_key(mk: &[u8; 16], passphrase: String) -> Self {
        // TEMP: The spec specifies a 512-bit output here because fetch
        // keys are intended to use the ristretto255 group, whose scalar
        // derivation requires wide (64 byte) input. We currently use X25519,
        // which takes a 32 byte seed, so we derive 32 bytes for now.
        //
        // TODO: Switch to 64 bytes when migrating the fetch key to ristretto255.
        let mut fetch_seed = [0u8; 32];
        hkdf::sha256(&mut fetch_seed, SOURCE_KDF_SALT, mk, b"sourcefetchkey")
            .expect("HKDF fetch key derivation failed");

        // sk_S^APKE is a hybrid key requiring two sub-derivations:
        // the DH-AKEM and ML-KEM components are each derived with their own
        // label under the "sourceAPKEkey" namespace.
        let mut dh_seed = [0u8; 32];
        hkdf::sha256(&mut dh_seed, SOURCE_KDF_SALT, mk, b"sourceAPKEkey-dh")
            .expect("HKDF APKE DH key derivation failed");

        let mut mlkem_seed = [0u8; 64];
        hkdf::sha256(&mut mlkem_seed, SOURCE_KDF_SALT, mk, b"sourceAPKEkey-mlkem")
            .expect("HKDF APKE ML-KEM key derivation failed");

        let mut pke_seed = [0u8; 32];
        hkdf::sha256(&mut pke_seed, SOURCE_KDF_SALT, mk, b"sourcePKEkey")
            .expect("HKDF PKE key derivation failed");

        // Create key pairs
        let (fetch_sk, fetch_pk): (DHPrivateKey, DHPublicKey) =
            deterministic_dh_keygen(fetch_seed).expect("Need Fetch keygen");

        let message_kp =
            kgen_deterministic_message(dh_seed, mlkem_seed).expect("Need SD-APKE keygen");

        let metadata_kp = kgen_deterministic_metadata(pke_seed).expect("Need X-Wing keygen");

        let session = SessionStorage {
            fpf_key: None,
            nr_key: None,
            fpf_signature: None,
        };

        Self {
            fetch_key: KeyPair {
                sk: fetch_sk,
                pk: fetch_pk,
            },
            message_keys: MessageKeyBundle::new(message_kp, metadata_kp),
            passphrase,
            session,
        }
    }

    /// Returns the public key material for this source.
    pub fn public(&self) -> SourcePublicView {
        SourcePublicView {
            fetch_pk: self.fetch_key.pk,
            apke_pk: self.message_keys.apke.public_key().clone(),
            message_pks: self.message_keys.public(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::xwing::XWING_PRIVATE_KEY_LEN;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Canonical BIP39 test vector: 16 zero bytes of entropy.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_initialize_with_passphrase() {
        let source1 = Source::from_passphrase(TEST_MNEMONIC).expect("valid mnemonic");
        let source2 = Source::from_passphrase(TEST_MNEMONIC).expect("valid mnemonic");

        assert_eq!(
            source1.passphrase, source2.passphrase,
            "Expected identical passphrase"
        );

        // SD-APKE keys (pk^APKE = (pk1, pk2))
        assert_eq!(
            source1.message_keys.apke.public_key().as_bytes(),
            source2.message_keys.apke.public_key().as_bytes(),
            "SD-APKE public key should be identical"
        );

        // Metadata keys
        assert_eq!(
            source1.message_keys.metadata_kp.public_key().as_bytes(),
            source2.message_keys.metadata_kp.public_key().as_bytes(),
            "XWING Encaps Key should be identical"
        );
        assert_eq!(
            source1.message_keys.metadata_kp.private_key().as_bytes(),
            source2.message_keys.metadata_kp.private_key().as_bytes(),
            "XWING Decaps Key should be identical"
        );
        assert_ne!(
            source1.message_keys.metadata_kp.private_key().as_bytes(),
            &[0u8; XWING_PRIVATE_KEY_LEN]
        );
    }

    proptest! {
        #[test]
        fn test_new_source_roundtrips_through_passphrase(seed in any::<u64>()) {
            let source = Source::new(ChaCha20Rng::seed_from_u64(seed));

            let restored = Source::from_passphrase(source.passphrase())
                .expect("generated mnemonic is valid");

            prop_assert_eq!(source.passphrase(), restored.passphrase());
            prop_assert_eq!(
                source.message_keys.apke.public_key().as_bytes(),
                restored.message_keys.apke.public_key().as_bytes(),
            );
        }
    }

    #[test]
    fn test_invalid_mnemonic_is_rejected() {
        let bad_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Source::from_passphrase(bad_checksum).is_err());

        assert!(Source::from_passphrase("hello world").is_err());
    }
}
