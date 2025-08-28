use rand_core::{CryptoRng, RngCore};

// TODO: These names are kinda bad
use crate::primitives::{FetchPrivateKey, FetchPublicKey, JournalistDHPublicKey, MessageEncPrivateKey, MessageEncPublicKey, MessagePQPSKDecapsKey, MessagePQPSKEncapsKey, MetadataDecapsKey, MetadataEncapsKey};
use crate::sign::{Signature, SigningKey, VerifyingKey};

/// Journalists signing key pair
/// Signed by the newsroom
/// Long-term
pub struct JournalistSigningKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}

impl JournalistSigningKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistSigningKeyPair {
        let sk = SigningKey::new(&mut rng).unwrap();
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
/// Medium-term
#[derive(Clone)]
pub struct JournalistFetchKeyPair {
    pub(crate) public_key: FetchPublicKey,
    private_key: FetchPrivateKey,
}

impl JournalistFetchKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistFetchKeyPair {
        let (private_key, public_key) =
            crate::primitives::generate_dh_keypair(&mut rng).expect("DH key generation failed");
        JournalistFetchKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist long term DH-AKEM keypair
/// Signed by the newsroom
#[derive(Clone)]
pub struct JournalistMessageEncKeyPair {
    pub(crate) public_key: MessageEncPublicKey,
    private_key: MessageEncPrivateKey,
}

impl JournalistMessageEncKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistMessageEncKeyPair {
        let (private_key, public_key) =
            crate::primitives::generate_dh_keypair(&mut rng).expect("DH key generation failed");
        JournalistMessageEncKeyPair {
            private_key: MessageEncPrivateKey::new(private_key),
            public_key: MessageEncPublicKey::new(public_key),
        }
    }
}

/// Journalist ephemeral KEM key pair
/// Signed by the journalist signing key
pub struct JournalistEphemeralKEMKeyPair {
    pub(crate) public_key: MessageEncPublicKey,
    private_key: MessageEncPrivateKey,
}

impl JournalistEphemeralKEMKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralKEMKeyPair {
        // Temporarily use DH keys as PPK placeholders
        let (dh_private_key, dh_public_key) =
            crate::primitives::generate(&mut rng).expect("DH key generation failed");
        let private_key = MessageEncPrivateKey::new(dh_private_key);
        let public_key = MessageEncPublicKey::new(dh_public_key);
        JournalistEphemeralKEMKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral PKE key pair
/// Signed by the journalist signing key
pub struct JournalistEphemeralMetadataKeyPair {
    pub(crate) public_key: MessageEncPublicKey,
    private_key: MessageEncPrivateKey,
}

impl JournalistEphemeralMetadataKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralMetadataKeyPair {
        // Temporarily use DH keys as PPK placeholders
        let (md_decaps, md_encaps) =
            crate::primitives::generate_xwing_keypair(&mut rng).expect("DH key generation failed");
        let private_key = MetadataDecapsKey::new(md_decaps);
        let public_key = MetadataEncapsKey::new(md_encaps);
        JournalistEphemeralMetadataKeyPair {
            private_key,
            public_key,
        }
    }
}

/// Journalist ephemeral DH-AKEM keypair
/// Signed by the journalist signing key
pub struct JournalistEphemeralMessageEncKeyPair {
    pub(crate) public_key: MessageEncPublicKey,
    private_key: MessageEncPrivateKey,
}

impl JournalistEphemeralMessageEncKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> JournalistEphemeralMessageEncKeyPair {
        let (private_key, public_key) =
            crate::primitives::generate_dh_keypair(&mut rng).expect("DH key generation failed");
        JournalistEphemeralMessageEncKeyPair {
            private_key,
            public_key,
        }
    }
}


// (new) 0.3 Keys

/// Journalist message encryption PSK (used for PQ secret)
///
/// One-time key
///
/// $J_epq$ in the specification.
pub struct JournalistOneTimeMessagePQKeyPair {
    pub(crate) public_key: MessagePQPSKEncapsKey,
    private_key: MessagePQPSKDecapsKey,
}

/// Journalist message encryption keypair
///
/// One-time key
///
/// $J_epke$ in the specification.
pub struct JournalistOneTimeMessageClassicalKeyPair {
    // TODO(ro): Fill in types here from primitives module
    pub(crate) public_key: MessageEncPublicKey,
    private_key: MessageEncPrivateKey,
}

/// Journalist metadata keypair
///
/// One-time key
///
/// $J_emd$ in the specification.
pub struct JournalistOneTimeMetadataKeyPair {
    pub(crate) public_key: MetadataEncapsKey,
    private_key: MetadataDecapsKey,
}

/// Ephemeral public keys for a journalist (without signature)
///
/// This struct contains just the ephemeral public keys that need to be signed.
/// Used for creating the message to sign in Step 3.2.
#[derive(Debug, Clone)]
pub struct JournalistEphemeralPublicKeys {
    /// One-time DH public key for DH-AKEM
    pub edhakem_pk: MessageEncPublicKey,
    /// One-time PQ public key for PQ secret
    pub epqkem_pk: MessagePQPSKEncapsKey,
    /// One-time PPK public key for Metadata
    pub emetadata_pk: MetadataEncapsKey,
}

impl JournalistEphemeralPublicKeys {
    /// Convert the ephemeral public keys to a byte array for signing
    ///
    /// Returns a 96-byte array containing the concatenated public keys:
    /// - edhakem_pk (32 bytes)
    /// - epqkem_pk (32 bytes)
    /// - emetadata_pk (32 bytes)
    pub fn into_bytes(self) -> [u8; 96] {
        let mut bytes = [0u8; 96];

        // Ephemeral DH public key (32 bytes)
        bytes[0..32].copy_from_slice(&self.edhakem_pk.into_bytes());

        // Ephemeral KEM public key (32 bytes)
        bytes[32..64].copy_from_slice(&self.epqkem_pk.into_bytes());

        // Ephemeral PKE public key (32 bytes)
        bytes[64..96].copy_from_slice(&self.emetadata_pk.into_bytes());

        bytes
    }
}

/// Ephemeral key set for a journalist (0.2)
#[derive(Debug, Clone)]
pub struct JournalistEphemeralKeyBundle {
    /// The ephemeral public keys
    pub public_keys: JournalistEphemeralPublicKeys,
    /// Journalist's signature over the ephemeral keys
    pub signature: Signature,
}

/// Journalist enrollment key bundle
///
/// This bundle is used to enroll a journalist into the system.
/// It contains the journalist's signing, fetching, and long-term DH key.
#[derive(Clone)]
pub struct JournalistEnrollmentKeyBundle {
    /// Journalist's signing key
    pub signing_key: VerifyingKey,
    /// Journalist's fetching key
    pub fetching_key: FetchPublicKey,

    // Journalist's DH key
    // TODO: Still using? Key of last resort? To discuss
    pub dh_key: JournalistDHPublicKey,
}

/// a 96 byte array of the required keys for enrollment
impl JournalistEnrollmentKeyBundle {
    pub fn into_bytes(self) -> [u8; 96] {
        let mut bytes = [0u8; 96];

        // Signing key verification key (32 bytes)
        bytes[0..32].copy_from_slice(&self.signing_key.into_bytes());

        // Fetching key public key (32 bytes)
        bytes[32..64].copy_from_slice(&self.fetching_key.into_bytes());

        // DH key public key (32 bytes)
        bytes[64..96].copy_from_slice(&self.dh_key.into_bytes());

        bytes
    }
}
