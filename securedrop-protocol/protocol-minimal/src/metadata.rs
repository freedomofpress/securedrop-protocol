//! SD-PKE: metadata encryption
//!
//! Spec pseudocode:
//! ```text
//! def KGen():
//!     (skS, pkS) = KEM_H.KGen()
//!     return (skS, pkS)
//!
//! def Enc(pkR, m):
//!     c, cp = HPKE.SealBase(pkR=pkR, info=None, aad=None, pt=m)
//!     return (c, cp)
//!
//! def Dec(skR, c, cp):
//!     m = HPKE.OpenBase(enc=c, skR=skR, info=None, aad=None, ct=cp)
//!     return m
//! ```

use alloc::vec::Vec;
use anyhow::Error;
use hpke_rs::{
    Hpke, Mode, hpke_types::AeadAlgorithm::Aes256Gcm, hpke_types::KdfAlgorithm::HkdfSha256,
    hpke_types::KemAlgorithm::XWingDraft06, libcrux::HpkeLibcrux,
};
use rand_core::{CryptoRng, RngCore};

use crate::constants::LEN_XWING_SHAREDSECRET_ENCAPS;
use crate::primitives::xwing::{XWingPrivateKey, XWingPublicKey, generate_xwing_keypair};

/// The recipient's metadata public key (`pk_R^PKE` in the spec).
#[derive(Debug, Clone)]
pub struct MetadataPublicKey(pub(crate) XWingPublicKey);

/// The recipient's metadata private key (`sk_R^PKE` in the spec).
pub struct MetadataPrivateKey(pub(crate) XWingPrivateKey);

/// A `(MetadataPrivateKey, MetadataPublicKey)` SD-PKE keypair.
pub struct MetadataKeyPair {
    sk: MetadataPrivateKey,
    pk: MetadataPublicKey,
}

impl MetadataKeyPair {
    /// Returns the public key.
    pub fn public_key(&self) -> &MetadataPublicKey {
        &self.pk
    }

    /// Returns the private key.
    pub fn private_key(&self) -> &MetadataPrivateKey {
        &self.sk
    }
}

/// SD-PKE ciphertext `(c, c')`: X-Wing encapsulation `c` together with HPKE
/// ciphertext `c'`.
#[derive(Debug, Clone)]
pub struct MetadataCiphertext {
    /// HPKE encapsulation output (`c` in the spec)
    pub(crate) c: [u8; LEN_XWING_SHAREDSECRET_ENCAPS],
    /// HPKE AEAD ciphertext (`c'` / `cp` in the spec)
    pub(crate) cp: Vec<u8>,
}

impl MetadataCiphertext {
    /// Total byte length of the ciphertext: encapsulation `c` + AEAD ciphertext `c'`.
    pub fn len(&self) -> usize {
        self.c.len() + self.cp.len()
    }
}

/// SD-PKE.KGen: generate a `MetadataKeyPair`.
///
/// # Errors
///
/// Returns an error if X-Wing key generation fails.
pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> Result<MetadataKeyPair, anyhow::Error> {
    let (sk_s, pk_s) = generate_xwing_keypair(rng)?;
    Ok(MetadataKeyPair {
        sk: MetadataPrivateKey(sk_s),
        pk: MetadataPublicKey(pk_s),
    })
}

/// SD-PKE.KGen (deterministic): derive a `MetadataKeyPair` from 32 bytes of seed material.
///
/// For use in passphrase-derived key generation only; do not use with random bytes
/// from a live RNG (use [`keygen`] instead).
///
/// # Errors
///
/// Returns an error if X-Wing key generation fails.
pub(crate) fn deterministic_keygen(randomness: [u8; 32]) -> Result<MetadataKeyPair, anyhow::Error> {
    use crate::primitives::xwing::deterministic_keygen as xwing_derand;
    let (sk_s, pk_s) = xwing_derand(randomness)?;
    Ok(MetadataKeyPair {
        sk: MetadataPrivateKey(sk_s),
        pk: MetadataPublicKey(pk_s),
    })
}

impl MetadataPublicKey {
    /// Returns the public key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// SD-PKE.Enc: encrypt message `m` to this key, returning `(c, c')`.
    ///
    /// `m` is the sender's serialized long-term APKE public key.
    pub fn encrypt(&self, m: &[u8]) -> MetadataCiphertext {
        let mut hpke = Hpke::<HpkeLibcrux>::new(Mode::Base, XWingDraft06, HkdfSha256, Aes256Gcm);
        let pk_r = self.0.clone().into();

        // MetadataPublicKey always holds a valid XWing key, so seal cannot fail.
        let (c_vec, cp) = hpke
            .seal(&pk_r, b"", b"", m, None, None, None)
            .expect("SD-PKE encryption failed");

        // XWing will always produce this length ciphertext, so this .expect is fine.
        let c: [u8; LEN_XWING_SHAREDSECRET_ENCAPS] = c_vec
            .try_into()
            .expect("X-Wing encapsulation output has unexpected length");

        MetadataCiphertext { c, cp }
    }
}

impl MetadataPrivateKey {
    /// Returns the private key as bytes.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// SD-PKE.Dec: decrypt `(c, c')` using this key, returning message `m`.
    ///
    /// # Errors
    ///
    /// Returns an error if HPKE decryption fails.
    pub fn decrypt(&self, ct: &MetadataCiphertext) -> Result<Vec<u8>, Error> {
        let hpke = Hpke::<HpkeLibcrux>::new(Mode::Base, XWingDraft06, HkdfSha256, Aes256Gcm);
        let sk_r = self.0.clone().into();

        hpke.open(&ct.c, &sk_r, b"", b"", &ct.cp, None, None, None)
            .map_err(|e| anyhow::anyhow!("SD-PKE decryption failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn get_rng() -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS random source failed");
        ChaCha20Rng::from_seed(seed)
    }

    proptest! {
        #[test]
        fn test_metadata_encrypt_decrypt_roundtrip(m in proptest::collection::vec(any::<u8>(), 0..200)) {
            let mut rng = get_rng();
            let kp = keygen(&mut rng).expect("KGen failed");

            let ct = kp.public_key().encrypt(&m);
            let decrypted = kp.private_key().decrypt(&ct).expect("Decryption failed");

            prop_assert_eq!(m, decrypted);
        }
    }

    #[test]
    fn test_metadata_decrypt_wrong_key_fails() {
        let mut rng = get_rng();
        let kp = keygen(&mut rng).expect("KGen failed");
        let wrong_kp = keygen(&mut rng).expect("KGen failed");

        let ct = kp.public_key().encrypt(b"some sender apke key bytes");
        assert!(wrong_kp.private_key().decrypt(&ct).is_err());
    }
}
