use rand_core::{CryptoRng, RngCore};

use crate::primitives::mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey};
use crate::primitives::xwing::{XWingPrivateKey, XWingPublicKey};
use crate::primitives::{
    PPKPrivateKey, PPKPublicKey, dh_akem::DhAkemPrivateKey, dh_akem::DhAkemPublicKey,
    x25519::DHPrivateKey, x25519::DHPublicKey,
};
use crate::sign::{SelfSignature, Signature, SigningKey, VerifyingKey};

/// Journalists signing key pair
/// Signed by the newsroom
/// Long-term, same in 0.3
pub struct JournalistSigningKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}

impl JournalistSigningKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistSigningKeyPair {
        let sk = SigningKey::new(&mut rng).expect("Signing key generation should succeed");
        let vk = sk.vk;
        JournalistSigningKeyPair { vk, sk }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.sk.sign(message)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// Journalist fetching key pair
/// Signed by the newsroom
/// Medium-term X25519, same in 0.3
#[derive(Clone)]
pub struct JournalistFetchKeyPair {
    pub public_key: DHPublicKey,
    pub(crate) private_key: DHPrivateKey,
}

impl JournalistFetchKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistFetchKeyPair {
        let (private_key, public_key) = crate::primitives::x25519::generate_dh_keypair(&mut rng)
            .expect("DH key generation failed");
        JournalistFetchKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist medium term keypair
/// Signed by the newsroom
///
/// Only used in 0.2
#[deprecated]
#[derive(Clone)]
pub struct JournalistDHKeyPair {
    pub public_key: DHPublicKey,
    pub(crate) private_key: DHPrivateKey,
}

impl JournalistDHKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistDHKeyPair {
        let (private_key, public_key) = crate::primitives::x25519::generate_dh_keypair(&mut rng)
            .expect("DH key generation failed");
        JournalistDHKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral KEM key pair
/// Signed by the journalist signing key
/// Only used in 0.2
#[deprecated]
pub struct JournalistEphemeralKEMKeyPair {
    pub public_key: PPKPublicKey,
    pub(crate) private_key: PPKPrivateKey,
}

impl JournalistEphemeralKEMKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralKEMKeyPair {
        // Temporarily use DH keys as PPK placeholders
        let (dh_private_key, dh_public_key) =
            crate::primitives::x25519::generate_dh_keypair(&mut rng)
                .expect("DH key generation failed");
        let private_key = PPKPrivateKey::new(dh_private_key);
        let public_key = PPKPublicKey::new(dh_public_key);
        JournalistEphemeralKEMKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral PKE key pair
/// Signed by the journalist signing key
/// Only used in 0.2
#[deprecated]
pub struct JournalistEphemeralPKEKeyPair {
    pub(crate) public_key: PPKPublicKey,
    private_key: PPKPrivateKey,
}

impl JournalistEphemeralPKEKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralPKEKeyPair {
        // Temporarily use DH keys as PPK placeholders
        let (dh_private_key, dh_public_key) =
            crate::primitives::x25519::generate_dh_keypair(&mut rng)
                .expect("DH key generation failed");
        let private_key = PPKPrivateKey::new(dh_private_key);
        let public_key = PPKPublicKey::new(dh_public_key);
        JournalistEphemeralPKEKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral DH-AKEM keypair
/// Signed by the journalist signing key
/// Only used in 0.2
#[deprecated]
pub struct JournalistEphemeralDHKeyPair {
    pub(crate) public_key: DHPublicKey,
    private_key: DHPrivateKey,
}

impl JournalistEphemeralDHKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralDHKeyPair {
        let (private_key, public_key) = crate::primitives::x25519::generate_dh_keypair(&mut rng)
            .expect("DH key generation failed");
        JournalistEphemeralDHKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist message encryption PSK (used for PQ secret)
///
/// One-time key
///
/// $J_epq$ in the specification.
#[derive(Debug, Clone)]
pub struct JournalistOneTimeMessagePQKeyPair {
    pub public_key: MLKEM768PublicKey,
    pub(crate) private_key: MLKEM768PrivateKey,
}

impl JournalistOneTimeMessagePQKeyPair {
    pub fn new(
        pubkey: MLKEM768PublicKey,
        priv_key: MLKEM768PrivateKey,
    ) -> JournalistOneTimeMessagePQKeyPair {
        JournalistOneTimeMessagePQKeyPair {
            public_key: (pubkey),
            private_key: (priv_key),
        }
    }

    /// Generate a new one-time message PQ key pair
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> JournalistOneTimeMessagePQKeyPair {
        let (private_key, public_key) =
            crate::primitives::mlkem::generate_mlkem768_keypair(&mut rng)
                .expect("MLKEM-768 key generation failed");
        JournalistOneTimeMessagePQKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist message encryption keypair
///
/// One-time key
///
/// $J_epke$ in the specification.
#[derive(Debug, Clone)]
pub struct JournalistOneTimeMessageClassicalKeyPair {
    pub public_key: DhAkemPublicKey,
    pub(crate) private_key: DhAkemPrivateKey,
}

impl JournalistOneTimeMessageClassicalKeyPair {
    pub fn new(
        pubkey: DhAkemPublicKey,
        priv_key: DhAkemPrivateKey,
    ) -> JournalistOneTimeMessageClassicalKeyPair {
        JournalistOneTimeMessageClassicalKeyPair {
            public_key: (pubkey),
            private_key: (priv_key),
        }
    }

    /// Generate a new one-time message classical key pair
    pub fn generate<R: RngCore + CryptoRng>(
        mut rng: R,
    ) -> JournalistOneTimeMessageClassicalKeyPair {
        let (private_key, public_key) =
            crate::primitives::dh_akem::generate_dh_akem_keypair(&mut rng)
                .expect("DH-AKEM key generation failed");
        JournalistOneTimeMessageClassicalKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist metadata keypair
///
/// One-time key
///
/// $J_emd$ in the specification.
#[derive(Debug, Clone)]
pub struct JournalistOneTimeMetadataKeyPair {
    pub public_key: XWingPublicKey,
    pub(crate) private_key: XWingPrivateKey,
}

impl JournalistOneTimeMetadataKeyPair {
    pub fn new(
        pubkey: XWingPublicKey,
        priv_key: XWingPrivateKey,
    ) -> JournalistOneTimeMetadataKeyPair {
        JournalistOneTimeMetadataKeyPair {
            public_key: (pubkey),
            private_key: (priv_key),
        }
    }

    /// Generate a new metadata keypair
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> JournalistOneTimeMetadataKeyPair {
        let (private_key, public_key) = crate::primitives::xwing::generate_xwing_keypair(&mut rng)
            .expect("XWING key generation failed");
        JournalistOneTimeMetadataKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist medium or long-term DH-AKEM key used for sending replies
#[derive(Debug, Clone)]
pub struct JournalistReplyClassicalKeyPair {
    pub public_key: DhAkemPublicKey,
    pub(crate) private_key: DhAkemPrivateKey,
}

impl JournalistReplyClassicalKeyPair {
    pub fn new(
        pubkey: DhAkemPublicKey,
        priv_key: DhAkemPrivateKey,
    ) -> JournalistReplyClassicalKeyPair {
        JournalistReplyClassicalKeyPair {
            public_key: (pubkey),
            private_key: (priv_key),
        }
    }

    /// Generate a new medium/long-term keypair for sending replies
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> JournalistReplyClassicalKeyPair {
        let (private_key, public_key) =
            crate::primitives::dh_akem::generate_dh_akem_keypair(&mut rng)
                .expect("DH-AKEM key generation failed");
        JournalistReplyClassicalKeyPair {
            private_key,
            public_key,
        }
    }
}

/// One-time public keys for a journalist (without signature)
///
/// This struct contains just the one-time public keys that need to be signed.
/// Used for creating the message to sign in Step 3.2.
///
/// Updated for 0.3 spec with new key types:
/// - J_{epq} (MLKEM-768) for message enc PSK (one-time)
/// - J_{epke} (DH-AKEM) for message enc (one-time)
/// - J_{emd} (XWING) for metadata enc (one-time)
/// - Note that all the one-time keys are for messages received
/// TODO: Use JournalistOneTimeKeypairs::pubkeys()
#[derive(Debug, Clone)]
pub struct JournalistOneTimePublicKeys {
    /// One-time MLKEM-768 public key for message enc PSK (one-time)
    pub one_time_message_pq_pk: MLKEM768PublicKey,
    /// One-time DH-AKEM public key for message enc (one-time)
    pub one_time_message_pk: DhAkemPublicKey,
    /// One-time XWING public key for metadata enc (one-time)
    pub one_time_metadata_pk: XWingPublicKey,
}

impl JournalistOneTimePublicKeys {
    /// Convert the one-time public keys to a byte array for signing
    ///
    /// Returns a byte array containing the concatenated public keys:
    /// - one_time_message_pq_pk (1184 bytes) - MLKEM-768
    /// - one_time_message_pk (32 bytes) - DH-AKEM
    /// - one_time_metadata_pk (1216 bytes) - XWING
    ///
    /// Total: 2432 bytes
    pub fn into_bytes(self) -> [u8; 2432] {
        let mut bytes = [0u8; 2432];

        // One-time MLKEM-768 public key (1184 bytes)
        bytes[0..1184].copy_from_slice(self.one_time_message_pq_pk.as_bytes());

        // One-time DH-AKEM public key (32 bytes)
        bytes[1184..1216].copy_from_slice(self.one_time_message_pk.as_bytes());

        // One-time XWING public key (1216 bytes)
        bytes[1216..2432].copy_from_slice(self.one_time_metadata_pk.as_bytes());

        bytes
    }
}

/// One-time public key set for a journalist
#[derive(Debug, Clone)]
pub struct JournalistOneTimeKeyBundle {
    /// The one-time public keys
    pub public_keys: JournalistOneTimePublicKeys,
    /// Journalist's signature over the one-time keys
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct JournalistLongtermPublicKeys {
    pub reply_key: DhAkemPublicKey,
    pub fetch_key: DHPublicKey,
}

impl JournalistLongtermPublicKeys {
    /// Convert public keys to a byte array for signing
    ///
    /// Returns a byte array containing the concatenated public keys:
    /// - fetch_key (32 bytes) - DH
    /// - long-term reply (32 bytes) - DH-AKEM
    ///
    /// Total: 64 bytes
    pub fn into_bytes(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        // DH fetching public key (32 bytes)
        bytes[0..32].copy_from_slice(&self.fetch_key.into_bytes());

        // DH-AKEM reply public key (32 bytes)
        bytes[32..64].copy_from_slice(self.reply_key.as_bytes());

        bytes
    }
}

/// One-time keystore (public and private) for a journalist
/// TODO: improve/refactor with OneTimeKeyBundle
/// TODO: use native hpke-rs types
#[derive(Debug, Clone)]
pub struct JournalistOneTimeKeypairs {
    pub dh_akem: JournalistOneTimeMessageClassicalKeyPair,
    pub pq_kem_psk: JournalistOneTimeMessagePQKeyPair,
    pub metadata: JournalistOneTimeMetadataKeyPair,
}

impl JournalistOneTimeKeypairs {
    pub fn new(
        dh_key: JournalistOneTimeMessageClassicalKeyPair,
        pq_kem_psk_key: JournalistOneTimeMessagePQKeyPair,
        metadata_key: JournalistOneTimeMetadataKeyPair,
    ) -> JournalistOneTimeKeypairs {
        JournalistOneTimeKeypairs {
            dh_akem: dh_key,
            pq_kem_psk: pq_kem_psk_key,
            metadata: metadata_key,
        }
    }

    /// Generate a key bundle
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> JournalistOneTimeKeypairs {
        let dh_key = JournalistOneTimeMessageClassicalKeyPair::generate(&mut rng);
        let pq_kem_psk_key = JournalistOneTimeMessagePQKeyPair::generate(&mut rng);
        let metadata_key = JournalistOneTimeMetadataKeyPair::generate(&mut rng);
        JournalistOneTimeKeypairs::new(dh_key, pq_kem_psk_key, metadata_key)
    }

    pub fn pubkeys(&self) -> JournalistOneTimePublicKeys {
        JournalistOneTimePublicKeys {
            one_time_message_pq_pk: self.pq_kem_psk.public_key.clone(),
            one_time_message_pk: self.dh_akem.public_key.clone(),
            one_time_metadata_pk: self.metadata.public_key.clone(),
        }
    }
}

/// Journalist enrollment key bundle for 0.3 spec
///
/// This bundle is used to enroll a journalist into the system.
/// Long-term keys for a journalist
#[derive(Clone)]
pub struct JournalistEnrollmentKeyBundle {
    /// Journalist's signing key
    pub signing_key: VerifyingKey,
    /// Long-term keys
    pub public_keys: JournalistLongtermPublicKeys,
    /// Journalist's signature over their long-term keys
    pub self_signature: SelfSignature,
}
