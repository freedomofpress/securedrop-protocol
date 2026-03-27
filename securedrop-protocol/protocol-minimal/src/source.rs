use crate::VerifyingKey;
use crate::api::Api;
use crate::primitives::dh_akem::DhAkemPrivateKey;
use crate::primitives::dh_akem::DhAkemPublicKey;
use crate::primitives::dh_akem::deterministic_keygen as kgen_deterministic_dhakem;
use crate::primitives::mlkem::MLKEM768PublicKey;
use crate::primitives::mlkem::deterministic_keygen as kgen_deterministic_mlkem;
use crate::primitives::x25519::DHPrivateKey;
use crate::primitives::x25519::DHPublicKey;
use crate::primitives::x25519::deterministic_dh_keygen;
use crate::primitives::xwing::XWingPublicKey;
use crate::primitives::xwing::deterministic_keygen as kgen_deterministic_xwing;
use alloc::vec::Vec;
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{CryptoRng, RngCore};

use crate::ciphertext::Plaintext;
use crate::constants::*;
use crate::keys::*;
use crate::traits::private;
use crate::traits::{UserPublic, UserSecret};

// Fixed public salt for domain separation. Argon2id requires a salt;
// since source keys must be deterministic from the passphrase alone,
// we use a fixed application-specific value rather than a random one.
const SOURCE_PBKDF_SALT: &[u8] = b"securedrop-source-v1";

/// Sources: ingredients
/// Sources have a fetch key and an unsigned key bundle.
/// They reuse the dh-akem key within the keybundle where
/// journalists use a "reply key".
pub struct Source {
    fetch_key: DhFetchKeyPair,
    message_keys: MessageKeyBundle,
    passphrase: Vec<u8>,
    session: SessionStorage,
}

// Public-facing representation of a source,
// i.e., for receiving messages
pub struct SourcePublicView {
    fetch_pk: DHPublicKey,
    dhakem_pk: DhAkemPublicKey,
    message_pks: KeyBundlePublic,
}

impl UserPublic for SourcePublicView {
    fn fetch_pk(&self) -> &DHPublicKey {
        &self.fetch_pk
    }

    fn message_auth_pk(&self) -> &DhAkemPublicKey {
        &self.dhakem_pk
    }

    fn message_psk_pk(&self) -> &MLKEM768PublicKey {
        &self.message_pks.mlkem_pk
    }

    fn message_metadata_pk(&self) -> &XWingPublicKey {
        &self.message_pks.xwing_pk
    }

    fn message_enc_pk(&self) -> &DhAkemPublicKey {
        &self.message_pks.dhakem_pk
    }
}

impl Api for Source {
    fn newsroom_verifying_key(&self) -> Option<&VerifyingKey> {
        self.session.nr_key.as_ref()
    }

    fn set_newsroom_verifying_key(&mut self, key: VerifyingKey) {
        self.session.nr_key = Some(key);
    }
}

impl private::Sealed for Source {}

/// Private, common to all users, implemented for sources
impl UserSecret for Source {
    fn num_bundles(&self) -> usize {
        1
    }

    fn fetch_keypair(&self) -> (&DHPrivateKey, &DHPublicKey) {
        (&self.fetch_key.sk, &self.fetch_key.pk)
    }

    fn message_auth_keypair(&self) -> (&DhAkemPrivateKey, &DhAkemPublicKey) {
        (&self.message_keys.dh_akem.sk, &self.message_keys.dh_akem.pk)
    }

    fn build_message(&self, message: Vec<u8>) -> Plaintext {
        let mut reply_key_pq_psk = [0u8; LEN_MLKEM_ENCAPS_KEY];
        reply_key_pq_psk.copy_from_slice(self.message_keys.mlkem.pk.as_bytes());

        let mut fetch_pk = [0u8; LEN_DH_ITEM];
        fetch_pk.copy_from_slice(&self.fetch_key.pk.clone().into_bytes());

        let mut reply_key_pq_hybrid = [0u8; LEN_XWING_ENCAPS_KEY];
        reply_key_pq_hybrid.copy_from_slice(self.message_keys.xwing_md.pk.as_bytes());

        Plaintext {
            sender_reply_pubkey_pq_psk: reply_key_pq_psk,
            sender_fetch_key: fetch_pk,
            sender_reply_pubkey_hybrid: reply_key_pq_hybrid,
            msg: message,
        }
    }

    fn keybundles(&self) -> impl Iterator<Item = &MessageKeyBundle> {
        core::iter::once(&self.message_keys)
    }
}

impl Source {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        // Generate a random passphrase
        let mut passphrase = [0u8; 32];
        rng.fill_bytes(&mut passphrase);

        // Derive all keys from the passphrase
        let source = Self::from_passphrase(&passphrase);
        source
    }

    pub fn passphrase(&self) -> &[u8] {
        &self.passphrase
    }

    /// Derive the master key from a passphrase using Argon2id (step 4).
    ///
    /// Uses a fixed, public, domain-specific salt. The security of the master
    /// key rests entirely on the entropy of the passphrase.
    fn derive_master_key(passphrase: &[u8]) -> [u8; 64] {
        // OWASP minimum recommended parameters for Argon2id from here:
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
        let params = Params::new(19456, 2, 1, Some(64)).expect("valid Argon2id params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut mk = [0u8; 64];
        argon2
            .hash_password_into(passphrase, SOURCE_PBKDF_SALT, &mut mk)
            .expect("Argon2id master key derivation failed");
        mk
    }

    /// Reconstruct source keys from a passphrase (step 4).
    ///
    /// Derives a master key via [`Source::derive_master_key`], then derives
    /// each private key from the master key using a domain-separated KDF.
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        use blake2::{Blake2b, Digest};

        let mk = Self::derive_master_key(passphrase);

        let mut fetch_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        fetch_hasher.update(b"sourcefetchkey");
        fetch_hasher.update(mk);
        let fetch_result = fetch_hasher.finalize();

        // sk_S^APKE is a hybrid key requiring two sub-derivations:
        // the DH-AKEM and ML-KEM components are each derived with their own
        // label under the "sourceAPKEkey" namespace.
        let mut dh_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        dh_hasher.update(b"sourceAPKEkey-dh");
        dh_hasher.update(mk);
        let dh_result = dh_hasher.finalize();

        let mut kem_hasher = Blake2b::<blake2::digest::typenum::U64>::new();
        kem_hasher.update(b"sourceAPKEkey-mlkem");
        kem_hasher.update(mk);
        let kem_result = kem_hasher.finalize();

        let mut pke_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        pke_hasher.update(b"sourcePKEkey");
        pke_hasher.update(mk);
        let pke_result = pke_hasher.finalize();

        // Create key pairs
        let (dhakem_decaps, dhakem_encaps) =
            kgen_deterministic_dhakem(dh_result.into()).expect("Need DH-AKEM keygen");

        let (fetch_sk, fetch_pk): (DHPrivateKey, DHPublicKey) =
            deterministic_dh_keygen(fetch_result.into()).expect("Need Fetch keygen");

        // TODO: review derand kgen mechanism, see mlkem.rs
        let (mlkem_decaps, mlkem_encaps) =
            kgen_deterministic_mlkem(kem_result.into()).expect("Need MLKEM keygen");

        let (xwing_decaps, xwing_encaps) =
            kgen_deterministic_xwing(pke_result.into()).expect("Need X-Wing keygen");

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
            message_keys: {
                MessageKeyBundle::new(
                    KeyPair {
                        sk: dhakem_decaps,
                        pk: dhakem_encaps,
                    },
                    KeyPair {
                        sk: mlkem_decaps,
                        pk: mlkem_encaps,
                    },
                    KeyPair {
                        sk: xwing_decaps,
                        pk: xwing_encaps,
                    },
                )
            },
            passphrase: passphrase.to_vec(),
            session: session,
        }
    }
    pub fn public(&self) -> SourcePublicView {
        SourcePublicView {
            fetch_pk: self.fetch_key.pk.clone(),
            dhakem_pk: self.message_keys.dh_akem.pk.clone(),
            message_pks: self.message_keys.public(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{LEN_DHKEM_DECAPS_KEY, LEN_MLKEM_DECAPS_KEY, LEN_XWING_DECAPS_KEY};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_initialize_with_passphrase() {
        // Fixed seed RNG
        let mut rng = ChaCha20Rng::seed_from_u64(666);

        let mut passphrase_bytes: [u8; 32] = [0u8; 32];
        let _ = &rng.fill_bytes(&mut passphrase_bytes);

        let source1 = Source::from_passphrase(&passphrase_bytes.clone());
        let source2 = Source::from_passphrase(&passphrase_bytes);

        assert_eq!(
            source1.passphrase, source2.passphrase,
            "Expected identical passphrase"
        );

        // DH keys
        assert_eq!(
            source1.message_keys.dh_akem.pk.as_bytes(),
            source2.message_keys.dh_akem.pk.as_bytes(),
            "DH-AKEM Pubkey should be identical"
        );
        assert_eq!(
            source1.message_keys.dh_akem.sk.as_bytes(),
            source2.message_keys.dh_akem.sk.as_bytes(),
            "DH-AKEM Private Key should be identical"
        );
        assert_ne!(
            *source1.message_keys.dh_akem.sk.as_bytes(),
            [0u8; LEN_DHKEM_DECAPS_KEY]
        );

        // PQ KEM keys
        assert_eq!(
            source1.message_keys.mlkem.pk.as_bytes(),
            source2.message_keys.mlkem.pk.as_bytes(),
            "PQ KEM Encaps Key should be identical"
        );
        assert_eq!(
            source1.message_keys.mlkem.sk.as_bytes(),
            source2.message_keys.mlkem.sk.as_bytes(),
            "PQ KEM Decaps Key should be identical"
        );
        assert_ne!(
            *source1.message_keys.mlkem.sk.as_bytes(),
            [0u8; LEN_MLKEM_DECAPS_KEY]
        );

        // Metadata keys
        assert_eq!(
            source1.message_keys.xwing_md.pk.as_bytes(),
            source2.message_keys.xwing_md.pk.as_bytes(),
            "XWING Encaps Key should be identical"
        );
        assert_eq!(
            source1.message_keys.xwing_md.sk.as_bytes(),
            source2.message_keys.xwing_md.sk.as_bytes(),
            "XWING Decaps Key should be identical"
        );
        assert_ne!(
            *source1.message_keys.xwing_md.sk.as_bytes(),
            [0u8; LEN_XWING_DECAPS_KEY]
        );
    }
}
