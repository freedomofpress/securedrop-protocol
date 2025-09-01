use rand_core::{CryptoRng, RngCore};

use crate::primitives::{
    PPKPrivateKey, PPKPublicKey,
    x25519::{DHPrivateKey, DHPublicKey},
};

/// Source public keys needed for journalist to reply to a source
///
/// This contains the ephemeral keys that the source provided during their message submission.
#[derive(Debug, Clone)]
pub struct SourcePublicKeys {
    /// Source's ephemeral DH public key
    pub ephemeral_dh_pk: DHPublicKey,
    /// Source's ephemeral KEM public key
    pub ephemeral_kem_pk: PPKPublicKey,
    /// Source's ephemeral PKE public key
    pub ephemeral_pke_pk: PPKPublicKey,
    /// Source's fetching public key
    pub fetch_pk: DHPublicKey,
}

// TODO: Name these better

#[derive(Debug, Clone)]
pub struct SourceKeyBundle {
    pub fetch: SourceFetchKeyPair,
    pub long_term_dh: SourceDHKeyPair,
    pub kem: SourceKEMKeyPair,
    pub pke: SourcePKEKeyPair,
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

/// Generate a passphrase and the corresponding keys (via KDF).
impl SourceKeyBundle {
    /// Get the source's DH public key
    pub fn dh_public_key(&self) -> &DHPublicKey {
        &self.long_term_dh.public_key
    }

    /// Get the source's PKE public key
    pub fn pke_public_key(&self) -> &PPKPublicKey {
        &self.pke.public_key
    }

    /// Get the source's KEM public key
    pub fn kem_public_key(&self) -> &PPKPublicKey {
        &self.kem.public_key
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

        // DH key
        let mut dh_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        dh_hasher.update(b"SD_DH_KEY");
        dh_hasher.update(passphrase);
        let dh_result = dh_hasher.finalize();

        // Fetch key
        let mut fetch_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        fetch_hasher.update(b"SD_FETCH_KEY");
        fetch_hasher.update(passphrase);
        let fetch_result = fetch_hasher.finalize();

        // PKE key
        let mut pke_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        pke_hasher.update(b"SD_PKE_KEY");
        pke_hasher.update(passphrase);
        let pke_result = pke_hasher.finalize();

        // KEM key
        let mut kem_hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        kem_hasher.update(b"SD_KEM_KEY");
        kem_hasher.update(passphrase);
        let kem_result = kem_hasher.finalize();

        // Create key pairs
        Self {
            fetch: SourceFetchKeyPair::new(fetch_result.into()),
            long_term_dh: SourceDHKeyPair::new(dh_result.into()),
            kem: SourceKEMKeyPair::new(kem_result.into()),
            pke: SourcePKEKeyPair::new(pke_result.into()),
        }
    }
}
