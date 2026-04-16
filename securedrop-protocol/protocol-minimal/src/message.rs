//! SD-APKE: SecureDrop authenticated public-key encryption.
//!
//! Spec pseudocode:
//! ```text
//! def KGen():
//!     (sk1, pk1) = AKEM.KGen()
//!     (sk2, pk2) = KEM_PQ.KGen()
//!     sk = (sk1, sk2)
//!     pk = (pk1, pk2)
//!     return (sk, pk)
//!
//! def AuthEnc(sk=(skS1, skS2), pk=(pkR1, pkR2), m, ad, info):
//!     (c2, K2) = KEM_PQ.Encap(pkR=pkR2)
//!     (c1, cp) = pskAEnc(skS=skS1, pkR=pkR1, psk=K2, m=m, ad=ad, info=c2+info)
//!     return ((c1, cp), c2)
//!
//! def AuthDec(sk=(skR1, skR2), pk=(pkS1, pkS2), c1, cp, c2, ad, info):
//!     K2 = KEM_PQ.Decap(skR=skR2, enc=c2)
//!     m = pskADec(pkS=pkS1, skR=skR1, psk=K2, c1=c1, cp=cp, ad=ad, info=c2+info)
//!     return m
//! ```

use alloc::vec::Vec;
use anyhow::Error;
use hpke_rs::{
    Hpke, HpkePrivateKey, HpkePublicKey, Mode, hpke_types::AeadAlgorithm::Aes256Gcm,
    hpke_types::KdfAlgorithm::HkdfSha256, hpke_types::KemAlgorithm::DhKem25519,
    libcrux::HpkeLibcrux,
};
use libcrux_kem::MlKem768;
use libcrux_traits::kem::owned::Kem;
use rand_core::{CryptoRng, RngCore};

use crate::constants::{LEN_DHKEM_SHAREDSECRET_ENCAPS, LEN_MLKEM_SHAREDSECRET_ENCAPS};
use crate::primitives::dh_akem::deterministic_keygen as dhakem_derand;
use crate::primitives::dh_akem::{DhAkemPrivateKey, DhAkemPublicKey, generate_dh_akem_keypair};
use crate::primitives::mlkem::{
    MLKEM768PrivateKey, MLKEM768PublicKey, deterministic_keygen as mlkem_derand,
    generate_mlkem768_keypair,
};

// PSK ID per spec §pskAPKE
// spec: PSK_ID = "SD-pskAPKE"
const PSK_ID: &[u8] = b"SD-pskAPKE";

// ML-KEM-768 encaps randomness size (32 bytes, not the 64-byte keygen seed)
const LEN_MLKEM_ENCAPS_RAND: usize = 32;

/// The SD-APKE public key tuple `pk^APKE = (pk1, pk2)`.
///
/// - `pk1`: DHKEM(X25519) component (`pk^AKEM`)
/// - `pk2`: ML-KEM-768 component (`pk^PQ`)
#[derive(Debug, Clone)]
pub struct MessagePublicKey {
    pub(crate) dhakem: DhAkemPublicKey,  // pk1 in spec
    pub(crate) mlkem: MLKEM768PublicKey, // pk2 in spec
}

/// The SD-APKE private key tuple `sk^APKE = (sk1, sk2)`.
///
/// - `sk1`: DHKEM(X25519) component (`sk^AKEM`)
/// - `sk2`: ML-KEM-768 component (`sk^PQ`)
pub struct MessagePrivateKey {
    pub(crate) dhakem: DhAkemPrivateKey,  // sk1 in spec
    pub(crate) mlkem: MLKEM768PrivateKey, // sk2 in spec
}

/// A `(MessagePrivateKey, MessagePublicKey)` SD-APKE keypair.
pub struct MessageKeyPair {
    sk: MessagePrivateKey,
    pk: MessagePublicKey,
}

impl MessageKeyPair {
    /// Returns the public key.
    pub fn public_key(&self) -> &MessagePublicKey {
        &self.pk
    }

    /// Returns the private key.
    pub fn private_key(&self) -> &MessagePrivateKey {
        &self.sk
    }
}

impl MessagePublicKey {
    /// Serialize the key tuple in canonical byte order: `pk1 || pk2`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.dhakem.as_bytes());
        out.extend_from_slice(self.mlkem.as_bytes());
        out
    }

    /// Deserialize from `pk1 || pk2` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice has incorrect length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        use crate::primitives::dh_akem::DH_AKEM_PUBLIC_KEY_LEN;
        use crate::primitives::mlkem::MLKEM768_PUBLIC_KEY_LEN;

        if bytes.len() != DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN {
            return Err(anyhow::anyhow!(
                "Invalid MessagePublicKey length: expected {}, got {}",
                DH_AKEM_PUBLIC_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN,
                bytes.len()
            ));
        }

        let dhakem_bytes: [u8; DH_AKEM_PUBLIC_KEY_LEN] = bytes[..DH_AKEM_PUBLIC_KEY_LEN]
            .try_into()
            .expect("checked length");
        let mlkem_bytes: [u8; MLKEM768_PUBLIC_KEY_LEN] = bytes[DH_AKEM_PUBLIC_KEY_LEN..]
            .try_into()
            .expect("checked length");

        Ok(Self {
            dhakem: DhAkemPublicKey::from_bytes(dhakem_bytes),
            mlkem: MLKEM768PublicKey::from_bytes(mlkem_bytes),
        })
    }
}

/// SD-APKE ciphertext `((c1, cp), c2)`.
#[derive(Debug, Clone)]
pub struct MessageCiphertext {
    /// HPKE encapsulation output (`c1` in the spec)
    pub(crate) c1: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS],
    /// HPKE AEAD ciphertext (`cp` / `c'` in the spec)
    pub(crate) cp: Vec<u8>,
    /// ML-KEM-768 encapsulation used as PSK (`c2` in the spec)
    pub(crate) c2: [u8; LEN_MLKEM_SHAREDSECRET_ENCAPS],
}

impl MessageCiphertext {
    /// Total byte length: `c1 + cp + c2`.
    pub fn len(&self) -> usize {
        self.c1.len() + self.cp.len() + self.c2.len()
    }
}

/// SD-APKE.KGen: generate a `MessageKeyPair`.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> Result<MessageKeyPair, Error> {
    let (sk1, pk1) = generate_dh_akem_keypair(rng)?; // AKEM.KGen()
    let (sk2, pk2) = generate_mlkem768_keypair(rng)?; // KEM_PQ.KGen()
    Ok(MessageKeyPair {
        sk: MessagePrivateKey {
            dhakem: sk1,
            mlkem: sk2,
        },
        pk: MessagePublicKey {
            dhakem: pk1,
            mlkem: pk2,
        },
    })
}

/// SD-APKE.KGen (deterministic): derive a `MessageKeyPair` from seed material.
///
/// For use in passphrase-derived key generation only.
pub(crate) fn deterministic_keygen(
    dh_seed: [u8; 32],
    mlkem_seed: [u8; 64],
) -> Result<MessageKeyPair, Error> {
    let (sk1, pk1) = dhakem_derand(dh_seed)?;
    let (sk2, pk2) = mlkem_derand(mlkem_seed)?;
    Ok(MessageKeyPair {
        sk: MessagePrivateKey {
            dhakem: sk1,
            mlkem: sk2,
        },
        pk: MessagePublicKey {
            dhakem: pk1,
            mlkem: pk2,
        },
    })
}

/// SD-APKE.AuthEnc: encrypt message `m` from sender to recipient.
///
/// - `sk = (skS1, skS2)`: sender's SD-APKE private key
/// - `pk = (pkR1, pkR2)`: recipient's SD-APKE public key
/// - `ad`: associated data
/// - `info`: caller-supplied info (spec prepends `c2` internally: `info = c2 + info`)
///
/// # Errors
///
/// Returns an error if ML-KEM encapsulation or HPKE sealing fails.
pub fn auth_enc<R: RngCore + CryptoRng>(
    rng: &mut R,
    sk: &MessagePrivateKey, // (skS1, skS2)
    pk: &MessagePublicKey,  // (pkR1, pkR2)
    m: &[u8],
    ad: &[u8],
    info: &[u8],
) -> Result<MessageCiphertext, Error> {
    let mut hpke = Hpke::<HpkeLibcrux>::new(Mode::AuthPsk, DhKem25519, HkdfSha256, Aes256Gcm);

    let mut randomness = [0u8; LEN_MLKEM_ENCAPS_RAND];
    rng.fill_bytes(&mut randomness);

    // (c2, K2) = KEM_PQ.Encap(pkR=pkR2)
    let (k2, c2) = MlKem768::encaps(pk.mlkem.as_bytes(), &randomness)
        .map_err(|e| anyhow::anyhow!("ML-KEM encapsulation failed: {:?}", e))?;

    // (c1, cp) = pskAEnc(skS=skS1, pkR=pkR1, psk=K2, m=m, ad=ad, info=c2+info)
    let pkr1: HpkePublicKey = pk.dhakem.clone().into();
    let sks1: HpkePrivateKey = sk.dhakem.clone().into();

    let mut full_info = Vec::new();
    full_info.extend_from_slice(&c2);
    full_info.extend_from_slice(info);

    let (c1_vec, cp) = hpke
        .seal(
            &pkr1,
            &full_info,
            ad,
            m,
            Some(&k2),
            Some(PSK_ID),
            Some(&sks1),
        )
        .map_err(|e| anyhow::anyhow!("SD-APKE AuthEnc failed: {:?}", e))?;

    // c1 is always LEN_DHKEM_SHAREDSECRET_ENCAPS bytes for DHKEM(X25519)
    let c1: [u8; LEN_DHKEM_SHAREDSECRET_ENCAPS] = c1_vec
        .try_into()
        .expect("DHKEM(X25519) encapsulation output has unexpected length");

    Ok(MessageCiphertext { c1, cp, c2 })
}

/// SD-APKE.AuthDec: decrypt ciphertext from sender.
///
/// - `sk = (skR1, skR2)`: recipient's SD-APKE private key
/// - `pk = (pkS1, pkS2)`: sender's SD-APKE public key
/// - `ad`: associated data
/// - `info`: caller-supplied info (spec prepends `c2` internally: `info = c2 + info`)
///
/// # Errors
///
/// Returns an error if ML-KEM decapsulation or HPKE opening fails.
pub fn auth_dec(
    sk: &MessagePrivateKey, // (skR1, skR2)
    pk: &MessagePublicKey,  // (pkS1, pkS2)
    ct: &MessageCiphertext,
    ad: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, Error> {
    let hpke = Hpke::<HpkeLibcrux>::new(Mode::AuthPsk, DhKem25519, HkdfSha256, Aes256Gcm);

    // K2 = KEM_PQ.Decap(skR=skR2, enc=c2)
    let k2 = MlKem768::decaps(&ct.c2, sk.mlkem.as_bytes())
        .map_err(|e| anyhow::anyhow!("ML-KEM decapsulation failed: {:?}", e))?;

    // m = pskADec(pkS=pkS1, skR=skR1, psk=K2, c1=c1, cp=cp, ad=ad, info=c2+info)
    let skr1: HpkePrivateKey = sk.dhakem.clone().into();
    let pks1: HpkePublicKey = pk.dhakem.clone().into();

    let mut full_info = Vec::new();
    full_info.extend_from_slice(&ct.c2);
    full_info.extend_from_slice(info);

    hpke.open(
        &ct.c1,
        &skr1,
        &full_info,
        ad,
        &ct.cp,
        Some(&k2),
        Some(PSK_ID),
        Some(&pks1),
    )
    .map_err(|e| anyhow::anyhow!("SD-APKE AuthDec failed: {:?}", e))
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
        fn test_auth_enc_dec_roundtrip(
            m in proptest::collection::vec(any::<u8>(), 0..200),
            ad in proptest::collection::vec(any::<u8>(), 0..64),
            info in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut rng = get_rng();
            let sender_kp = keygen(&mut rng).expect("KGen failed");
            let recipient_kp = keygen(&mut rng).expect("KGen failed");

            let ct = auth_enc(
                &mut rng,
                sender_kp.private_key(),
                recipient_kp.public_key(),
                &m, &ad, &info,
            ).expect("AuthEnc failed");

            let decrypted = auth_dec(
                recipient_kp.private_key(),
                sender_kp.public_key(),
                &ct, &ad, &info,
            ).expect("AuthDec failed");

            prop_assert_eq!(m, decrypted);
        }
    }

    #[test]
    fn test_auth_dec_wrong_recipient_fails() {
        let mut rng = get_rng();
        let sender_kp = keygen(&mut rng).expect("KGen failed");
        let recipient_kp = keygen(&mut rng).expect("KGen failed");
        let wrong_kp = keygen(&mut rng).expect("KGen failed");

        let ct = auth_enc(
            &mut rng,
            sender_kp.private_key(),
            recipient_kp.public_key(),
            b"secret",
            b"ad",
            b"info",
        )
        .expect("AuthEnc failed");

        assert!(
            auth_dec(
                wrong_kp.private_key(),
                sender_kp.public_key(),
                &ct,
                b"ad",
                b"info",
            )
            .is_err()
        );
    }
}
