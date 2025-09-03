use libcrux_kem::{Algorithm, key_gen_derand};
use libcrux_ml_kem::*;
use rand_core::{CryptoRng, RngCore};

use crate::primitives::{
    PPKPrivateKey, PPKPublicKey,
    dh_akem::{DhAkemPrivateKey, DhAkemPublicKey},
    mlkem::{MLKEM768PrivateKey, MLKEM768PublicKey},
    x25519::{DHPrivateKey, DHPublicKey},
    xwing::{XWingPrivateKey, XWingPublicKey},
};

/// This contains the sender keys for the source, provided during their message submission.
/// The DH-AKEM public key is provided in the outer metadata, and is needed to
/// decrypt the inner authenticated ciphertext.
/// The metadata key, PQ PSK key, and Fetching key are provided so that sources
/// can receive replies.
#[derive(Debug, Clone)]
pub struct SourcePublicKeys {
    /// Source's DH-AKEM public key
    pub message_dhakem_pk: DhAkemPublicKey,
    /// Source's PQ KEM PSK public key
    pub message_pq_psk_pk: MLKEM768PublicKey,
    /// Source's Metadata public key
    pub metadata_pk: XWingPublicKey,
    /// Source's fetching public key
    pub fetch_pk: DHPublicKey,
}

// TODO: Name these better

#[derive(Debug, Clone)]
pub struct SourceKeyBundle {
    pub fetch: SourceFetchKeyPair,
    pub long_term_dh: SourceMessageClassicalKeyPair,
    pub pq_kem_psk: SourceMessagePQKeyPair,
    pub metadata: SourceMetadataKeyPair,
}

#[derive(Debug, Clone)]
pub struct SourcePassphrase {
    /// TODO make a string
    pub passphrase: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SourceFetchKeyPair {
    pub public_key: DHPublicKey,
    pub(crate) private_key: DHPrivateKey,
}

impl SourceFetchKeyPair {
    /// Create a fetch key pair from private key bytes
    fn new(private_key_bytes: [u8; 32]) -> Self {
        let private_key = DHPrivateKey::from_bytes(private_key_bytes);

        let mut public_key_bytes = [0u8; 32];
        libcrux_curve25519::secret_to_public(&mut public_key_bytes, &private_key_bytes);
        let public_key = DHPublicKey::from_bytes(public_key_bytes);

        Self {
            public_key,
            private_key,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.clone().into_bytes()
    }
}

#[derive(Debug, Clone)]
#[deprecated]
pub struct SourceDHKeyPair {
    pub public_key: DHPublicKey,
    pub(crate) private_key: DHPrivateKey,
}

impl SourceDHKeyPair {
    /// Create a DH key pair from private key bytes
    fn new(private_key_bytes: [u8; 32]) -> Self {
        let private_key = DHPrivateKey::from_bytes(private_key_bytes);

        let mut public_key_bytes = [0u8; 32];
        libcrux_curve25519::secret_to_public(&mut public_key_bytes, &private_key_bytes);
        let public_key = DHPublicKey::from_bytes(public_key_bytes);

        Self {
            public_key,
            private_key,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.clone().into_bytes()
    }
}

#[derive(Debug, Clone)]
#[deprecated]
pub struct SourceKEMKeyPair {
    pub public_key: PPKPublicKey,
    pub(crate) private_key: PPKPrivateKey,
}

impl SourceKEMKeyPair {
    /// Create a KEM key pair from private key bytes
    fn new(private_key_bytes: [u8; 32]) -> Self {
        let private_key = PPKPrivateKey::new(DHPrivateKey::from_bytes(private_key_bytes));

        let mut public_key_bytes = [0u8; 32];
        libcrux_curve25519::secret_to_public(&mut public_key_bytes, &private_key_bytes);
        let public_key = PPKPublicKey::new(DHPublicKey::from_bytes(public_key_bytes));

        Self {
            public_key,
            private_key,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.clone().into_bytes()
    }
}

#[derive(Debug, Clone)]
#[deprecated]
pub struct SourcePKEKeyPair {
    pub public_key: PPKPublicKey,
    pub(crate) private_key: PPKPrivateKey,
}

impl SourcePKEKeyPair {
    /// Create a PKE key pair from private key bytes
    fn new(private_key_bytes: [u8; 32]) -> Self {
        let private_key = PPKPrivateKey::new(DHPrivateKey::from_bytes(private_key_bytes));

        let mut public_key_bytes = [0u8; 32];
        libcrux_curve25519::secret_to_public(&mut public_key_bytes, &private_key_bytes);
        let public_key = PPKPublicKey::new(DHPublicKey::from_bytes(public_key_bytes));

        Self {
            public_key,
            private_key,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.clone().into_bytes()
    }
}

// new 0.3 keys

/// Source message encryption PSK (used for PQ secret)
///
/// $S_pq$ in the specification.
#[derive(Debug, Clone)]
pub struct SourceMessagePQKeyPair {
    pub public_key: MLKEM768PublicKey,
    pub(crate) private_key: MLKEM768PrivateKey,
}

/// Source message encryption keypair (PQ PSK component)
impl SourceMessagePQKeyPair {
    /// Given a random seed, construct MLKEM768 encaps and decaps key.
    /// TODO: ***FOR PROOF OF CONCEPT ONLY!*** Not for production use.
    pub fn from_bytes(priv_key_bytes: [u8; 64]) -> SourceMessagePQKeyPair {
        let (sk, pk) = mlkem768::generate_key_pair(priv_key_bytes).into_parts();
        // TODO: use hpke-rs types in keys.rs
        let mlkem_encaps = MLKEM768PublicKey::from_bytes(pk.into());
        let mlkem_decaps = MLKEM768PrivateKey::from_bytes(sk.into());

        SourceMessagePQKeyPair {
            public_key: mlkem_encaps,
            private_key: mlkem_decaps,
        }
    }
}

/// Source message encryption keypair (classical component)
///
/// $S_dh$ in the specification.
#[derive(Debug, Clone)]
pub struct SourceMessageClassicalKeyPair {
    pub public_key: DhAkemPublicKey,
    pub(crate) private_key: DhAkemPrivateKey,
}

impl SourceMessageClassicalKeyPair {
    /// Given a random seed, construct XWING encaps and decaps key.
    /// TODO: ***FOR PROOF OF CONCEPT ONLY!*** Not for production use.
    pub fn from_bytes(seed_bytes: [u8; 64]) -> SourceMessageClassicalKeyPair {
        let alg = Algorithm::X25519;
        let (sk, pk) =
            key_gen_derand(alg, &seed_bytes).expect("Failed to generate DH-AKEM keypair");
        let sk_bytes = sk.encode().try_into().expect("error encoding dh-akem sk");
        let pk_bytes = pk.encode().try_into().expect("error encoding dh-akem pk");

        let md_encaps = DhAkemPublicKey::from_bytes(pk_bytes);
        let md_decaps = DhAkemPrivateKey::from_bytes(sk_bytes);

        SourceMessageClassicalKeyPair {
            public_key: (md_encaps),
            private_key: (md_decaps),
        }
    }
}

/// Source metadata (hybrid) keypair
///
/// $S_md$ in the specification.
#[derive(Debug, Clone)]
pub struct SourceMetadataKeyPair {
    pub public_key: XWingPublicKey,
    pub(crate) private_key: XWingPrivateKey,
}

impl SourceMetadataKeyPair {
    /// Given a random seed, construct XWING encaps and decaps key.
    /// TODO: ***FOR PROOF OF CONCEPT ONLY!*** Not for production use.
    pub fn from_bytes(seed_bytes: [u8; 64]) -> SourceMetadataKeyPair {
        let alg = Algorithm::XWingKemDraft06;
        let (sk, pk) = key_gen_derand(alg, &seed_bytes).expect("Failed to generate XWing keypair");
        let pk_bytes = pk
            .encode()
            .try_into()
            .expect("Error encoding xwing pk bytes");
        let sk_bytes = sk
            .encode()
            .try_into()
            .expect("Error encoding xwing sk bytes");

        let md_encaps = XWingPublicKey::from_bytes(pk_bytes);
        let md_decaps = XWingPrivateKey::from_bytes(sk_bytes);

        SourceMetadataKeyPair {
            public_key: md_encaps,
            private_key: md_decaps,
        }
    }
}

/// Generate a passphrase and the corresponding keys (via KDF).
impl SourceKeyBundle {
    /// Get the source's DH-AKEM  public key
    pub fn dh_public_key(&self) -> &DhAkemPublicKey {
        &self.long_term_dh.public_key
    }

    /// Get the source's metadata public key
    pub fn pke_public_key(&self) -> &XWingPublicKey {
        &self.metadata.public_key
    }

    /// Get the source's KEM public key
    pub fn kem_public_key(&self) -> &MLKEM768PublicKey {
        &self.pq_kem_psk.public_key
    }

    /// Get the source's fetch public key
    pub fn fetch_public_key(&self) -> &DHPublicKey {
        &self.fetch.public_key
    }

    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> (SourcePassphrase, SourceKeyBundle) {
        // Generate a random passphrase
        let mut passphrase = [0u8; 32];
        rng.fill_bytes(&mut passphrase);

        let source_passphrase = SourcePassphrase { passphrase };

        // Derive all keys from the passphrase
        let key_bundle = Self::from_passphrase(&passphrase);

        (source_passphrase, key_bundle)
    }

    /// Reconstruct keys from an existing passphrase
    ///
    /// TODO: I deviated a bit from the spec
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        use blake2::{Blake2b, Digest};

        // DH-AKEM key
        let mut dh_hasher = Blake2b::<blake2::digest::typenum::U64>::new();
        dh_hasher.update(b"SD_DH_KEY");
        dh_hasher.update(passphrase);
        let dh_result = dh_hasher.finalize();

        // Fetch key
        let mut fetch_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        fetch_hasher.update(b"SD_FETCH_KEY");
        fetch_hasher.update(passphrase);
        let fetch_result = fetch_hasher.finalize();

        // Metadata Key
        let mut pke_hasher = Blake2b::<blake2::digest::typenum::U64>::new();
        pke_hasher.update(b"SD_PKE_KEY");
        pke_hasher.update(passphrase);
        let pke_result = pke_hasher.finalize();

        // PQ KEM PSK key
        let mut kem_hasher = Blake2b::<blake2::digest::typenum::U64>::new();
        kem_hasher.update(b"SD_KEM_KEY");
        kem_hasher.update(passphrase);
        let kem_result = kem_hasher.finalize();

        // Create key pairs
        Self {
            fetch: SourceFetchKeyPair::new(fetch_result.into()),
            long_term_dh: SourceMessageClassicalKeyPair::from_bytes(dh_result.into()),
            pq_kem_psk: SourceMessagePQKeyPair::from_bytes(kem_result.into()),
            metadata: SourceMetadataKeyPair::from_bytes(pke_result.into()),
        }
    }
}
