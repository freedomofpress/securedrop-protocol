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

use crate::{
    message::MessagePublicKey,
    primitives::provider::hpke_rs::{Aes256Gcm, HkdfSha256, Hpke, HpkeLibcrux, Mode, XWingDraft06},
};
use alloc::string::String;
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};
use serde::de::Error as _;

use crate::primitives::xwing::{
    LEN_XWING_SHAREDSECRET_ENCAPS, XWING_PRIVATE_KEY_LEN, XWING_PUBLIC_KEY_LEN, XWingPrivateKey,
    XWingPublicKey, generate_xwing_keypair,
};

// TODO: maybe needs a better location
// DHAKEM_PKLEN + MLKEM768PK_LEN + AEAD_TAG_LEN = 32 + 1184 + 16
pub(crate) const LEN_METADATA_CIPHERTEXT: usize = 1232;

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

    /// Reconstruct a keypair from the raw X-Wing secret and public key bytes
    pub(crate) fn from_key_bytes(
        sk: [u8; XWING_PRIVATE_KEY_LEN],
        pk: [u8; XWING_PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            sk: MetadataPrivateKey(XWingPrivateKey::from_bytes(sk)),
            pk: MetadataPublicKey(XWingPublicKey::from_bytes(pk)),
        }
    }

    /// Raw X-Wing secret key bytes
    pub(crate) fn secret_bytes(&self) -> &[u8; XWING_PRIVATE_KEY_LEN] {
        self.sk.0.as_bytes()
    }

    /// Raw X-Wing public key bytes
    pub(crate) fn public_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        self.pk.0.as_bytes()
    }
}

/// SD-PKE ciphertext `(c, c')`: X-Wing encapsulation `c` together with HPKE
/// ciphertext `c'`.
#[derive(Debug, Clone)]
pub struct MetadataCiphertext {
    /// HPKE encapsulation output (`c` in the spec)
    pub(crate) c: [u8; LEN_XWING_SHAREDSECRET_ENCAPS],
    /// HPKE AEAD ciphertext (`c'` / `cp` in the spec)
    pub(crate) cp: [u8; LEN_METADATA_CIPHERTEXT],
}

impl MetadataCiphertext {
    /// Total byte length of the ciphertext: encapsulation `c` + AEAD ciphertext `c'`.
    pub fn len(&self) -> usize {
        // TODO: hax_lib::refine(self.c.len() == LEN_XWING_SHAREDSECRET_ENCAPS && self.cp.len() == LEN_METADATA_CIPHERTEXT)
        // This isn't the best, but hax is struggling to parse c.len()
        LEN_XWING_SHAREDSECRET_ENCAPS + LEN_METADATA_CIPHERTEXT
    }

    /// Wire encoding `c || cp`
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&self.c);
        out.extend_from_slice(&self.cp);
        out
    }

    /// Deserialize from the `c || cp` wire encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice is shorter than the encapsulation `c`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < LEN_XWING_SHAREDSECRET_ENCAPS {
            return Err(anyhow::anyhow!(
                "MetadataCiphertext too short: expected at least {}, got {}",
                LEN_XWING_SHAREDSECRET_ENCAPS,
                bytes.len()
            ));
        }
        let (c, cp) = bytes.split_at(LEN_XWING_SHAREDSECRET_ENCAPS);
        Ok(Self {
            c: c.try_into().expect("checked length"),
            cp: cp.to_vec(),
        })
    }
}

impl serde::Serialize for MetadataCiphertext {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for MetadataCiphertext {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let bytes = hex::decode(s.trim()).map_err(D::Error::custom)?;
        Self::from_bytes(&bytes).map_err(D::Error::custom)
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

    /// Deserialize from `pk_R^PKE` (X-Wing) bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has incorrect length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; XWING_PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Invalid MetadataPublicKey length: expected {}, got {}",
                XWING_PUBLIC_KEY_LEN,
                bytes.len()
            )
        })?;
        Ok(Self(XWingPublicKey::from_bytes(arr)))
    }
}

impl serde::Serialize for MetadataPublicKey {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for MetadataPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let bytes = hex::decode(s.trim()).map_err(D::Error::custom)?;
        Self::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

impl MetadataPrivateKey {
    /// Returns the private key as bytes.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// SD-PKE.Enc: encrypt message `m` to recipient key `pk_r`, returning `(c, c')`.
///
/// `m` is the sender's long-term APKE public key, which must be serializable.
pub(crate) fn encrypt(
    pk_r: &MetadataPublicKey,
    m: &MessagePublicKey,
) -> Result<MetadataCiphertext, anyhow::Error> {
    let mut hpke = Hpke::<HpkeLibcrux>::new(Mode::Base, XWingDraft06, HkdfSha256, Aes256Gcm);
    let pk_r_hpke = pk_r.0.clone().into();

    // MetadataPublicKey always holds a valid XWing key, so seal should not fail.
    let (c_vec, cp_vec) = match hpke.seal(&pk_r_hpke, b"", b"", &m.as_bytes(), None, None, None) {
        Ok((c_vec, cp_vec)) => (c_vec, cp_vec),
        Err(_) => return Err(anyhow::anyhow!("Metadata encryption failed")),
    };

    // XWing will always produce same length ciphertext
    let c: [u8; LEN_XWING_SHAREDSECRET_ENCAPS] = match c_vec.as_slice().try_into() {
        Ok(c) => c,
        Err(_) => {
            return Err(anyhow::anyhow!("Unexpected md encapsulated secret length"));
        }
    };

    let cp = match cp_vec.as_slice().try_into() {
        Ok(cp) => cp,
        Err(_) => return Err(anyhow::anyhow!("Unexpected md ciphertext length")),
    };

    Ok(MetadataCiphertext { c, cp })
}

/// SD-PKE.Dec: decrypt `(c, c')` using recipient key `sk_r`, returning message `m`.
///
/// # Errors
///
/// Returns an error if HPKE decryption fails.
pub fn decrypt(
    sk_r: &MetadataPrivateKey,
    ct: &MetadataCiphertext,
) -> Result<Vec<u8>, anyhow::Error> {
    let hpke = Hpke::<HpkeLibcrux>::new(Mode::Base, XWingDraft06, HkdfSha256, Aes256Gcm);
    let sk_r_hpke = sk_r.0.clone().into();

    hpke.open(&ct.c, &sk_r_hpke, b"", b"", &ct.cp, None, None, None)
        .map_err(|e| anyhow::anyhow!("SD-PKE decryption failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
    use crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{SeedableRng, TryRng};

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

            let mut fake_key_bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN] = [0u8; DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN];
            rng.try_fill_bytes(&mut fake_key_bytes);

            let m = MessagePublicKey::from_bytes(&fake_key_bytes).unwrap();

            let ct = encrypt(kp.public_key(), &m);
            let decrypted = decrypt(kp.private_key(), &ct.unwrap()).expect("Decryption failed");

            prop_assert_eq!(m.as_bytes(), decrypted);
        }
    }

    #[test]
    fn test_metadata_decrypt_wrong_key_fails() {
        let mut rng = get_rng();
        let kp = keygen(&mut rng).expect("KGen failed");
        let wrong_kp = keygen(&mut rng).expect("KGen failed");
        let mut fake_key_bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN] =
            [0u8; DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN];
        rng.try_fill_bytes(&mut fake_key_bytes);

        let m = MessagePublicKey::from_bytes(&fake_key_bytes).unwrap();

        let ct = encrypt(kp.public_key(), &m);
        assert!(decrypt(wrong_kp.private_key(), &ct.unwrap()).is_err());
    }
}
