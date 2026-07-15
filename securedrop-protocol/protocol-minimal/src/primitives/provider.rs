/// Import required crypto provider params.
/// Allows other modules to use crypto provider opaquely
///
pub mod curve25519 {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const SK_LEN: usize = libcrux_curve25519::DK_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const PK_LEN: usize = libcrux_curve25519::EK_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_DH_SHARE: usize = libcrux_curve25519::SS_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_curve25519::{ecdh, secret_to_public};

    #[cfg_attr(hax, hax_lib::opaque)]
    use libcrux_traits::kem::arrayref::Kem;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn x25519_keygen(
        public_key: &mut [u8; 32],
        secret_key: &mut [u8; 32],
        randomness: &[u8; 32],
    ) -> Result<(), libcrux_traits::kem::arrayref::KeyGenError> {
        libcrux_curve25519::X25519::keygen(public_key, secret_key, randomness)
    }
}

pub mod ed25519 {
    use rand_core::CryptoRng;

    /// Generate an ed25519 keypair
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn keygen<R: CryptoRng>(rng: &mut R) -> Result<([u8; 32], [u8; 32]), anyhow::Error> {
        let (sk, vk) = libcrux_ed25519::generate_key_pair(rng)
            .map_err(|_| anyhow::anyhow!("Key generation failed"))?;
        Ok((sk.into_bytes(), vk.into_bytes()))
    }

    /// Sign `payload` with Ed25519 secret key bytes.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn sign(payload: &[u8], private_key: &[u8; 32]) -> [u8; 64] {
        libcrux_ed25519::sign(payload, private_key).expect("Ed25519 signing is infallible")
    }

    /// Verify an Ed25519 `signature` over `payload` with verifying key bytes.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn verify(
        payload: &[u8],
        public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), anyhow::Error> {
        libcrux_ed25519::verify(payload, public_key, signature)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }

    /// Derive the Ed25519 public key from a secret key.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn secret_to_public(public_key: &mut [u8; 32], secret_key: &[u8; 32]) {
        libcrux_ed25519::secret_to_public(public_key, secret_key)
    }
}

pub mod rng {
    use rand_core::{CryptoRng, RngCore};

    /// Fill `dest` with random bytes from `rng`
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn fill_bytes<R: RngCore + CryptoRng, const N: usize>(
        rng: &mut R,
        dest: &mut [u8; N],
    ) {
        rng.fill_bytes(dest);
    }
}

pub mod uuid_parse {

    /// Parse a `Uuid` from bytes
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn from_slice(bytes: &[u8]) -> ::uuid::Uuid {
        ::uuid::Uuid::from_slice(bytes).expect("message id must be 16 bytes")
    }
}

pub mod kem {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_kem::{
        Algorithm, MlKem768, PrivateKey, PublicKey, key_gen, key_gen_derand,
    };
}

pub mod traits {

    // todo deprecate
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_traits::kem::owned::Kem as OwnedKem;
}

pub mod mlkem {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const KEY_GENERATION_SEED_SIZE: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_ml_kem::mlkem768;
}

pub mod chacha20poly1305 {

    #[cfg_attr(hax, hax_lib::opaque)]
    use libcrux_chacha20poly1305::AeadError;

    pub(crate) const KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;

    pub(crate) const NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;

    pub(crate) const TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;

    // #[cfg_attr(hax, hax_lib::opaque)]
    // pub(crate) use libcrux_chacha20poly1305::{decrypt, encrypt};

    #[cfg_attr(hax, hax_lib::ensures(|_result| future(ciphertext).len() == ciphertext.len()))]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn encrypt(
        key: &[u8; KEY_LEN],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        aad: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), AeadError> {
        libcrux_chacha20poly1305::encrypt(key, plaintext, ciphertext, aad, nonce).map(|_| ())
    }

    // Hax extraction is struggling with the types
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn decrypt(
        key: &[u8; KEY_LEN],
        plaintext: &mut [u8],
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), AeadError> {
        libcrux_chacha20poly1305::decrypt(key, plaintext, ciphertext, aad, nonce).map(|_| ())
    }
}

pub mod hkdf {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_hkdf::ExpandError;

    #[cfg_attr(hax, hax_lib::opaque)]
    use libcrux_hkdf::Algorithm;

    /// HKDF-SHA256
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn sha256(
        okm: &mut [u8],
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
    ) -> Result<(), ExpandError> {
        libcrux_hkdf::hkdf(Algorithm::Sha256, okm, salt, ikm, info)
    }
}

pub mod hpke_rs {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use hpke_rs::{
        Hpke, HpkePrivateKey, HpkePublicKey, Mode, hpke_types::AeadAlgorithm::ChaCha20Poly1305,
        hpke_types::KdfAlgorithm::HkdfSha256, hpke_types::KemAlgorithm::DhKem25519,
        hpke_types::KemAlgorithm::XWingDraft06, libcrux::HpkeLibcrux,
    };
}

pub mod constants {

    // Message ID (uuid) and KMID
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_MESSAGE_ID: usize = 16;
    // TODO: current implementation prepends the nonce to the encrypted message.
    // Recheck this when switching implementations.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_KMID: usize = crate::primitives::provider::chacha20poly1305::TAG_LEN
        + crate::primitives::provider::chacha20poly1305::NONCE_LEN
        + LEN_MESSAGE_ID;
}
