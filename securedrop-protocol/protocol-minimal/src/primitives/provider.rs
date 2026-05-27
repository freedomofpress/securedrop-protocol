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

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_ed25519::{
        SigningKey as LibCruxSigningKey, VerificationKey as LibCruxVerifyingKey,
    };

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_ed25519::{generate_key_pair, sign, verify};
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

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;

    // #[cfg_attr(hax, hax_lib::opaque)]
    // pub(crate) use libcrux_chacha20poly1305::{decrypt, encrypt};

    // Hax extraction is struggling with the types
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

pub mod hpke_rs {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use hpke_rs::{
        Hpke, HpkePrivateKey, HpkePublicKey, Mode, hpke_types::AeadAlgorithm::Aes256Gcm,
        hpke_types::KdfAlgorithm::HkdfSha256, hpke_types::KemAlgorithm::DhKem25519,
        hpke_types::KemAlgorithm::XWingDraft06, libcrux::HpkeLibcrux,
    };
}

pub mod constants {

    // Message ID (uuid) and KMID
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_MESSAGE_ID: usize = 16;
    // TODO: this will be aes-gcm and use AES GCM TagSize
    // TODO: current implementation prepends the nonce to the encrypted message.
    // Recheck this when switching implementations.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_KMID: usize = crate::primitives::provider::chacha20poly1305::TAG_LEN
        + crate::primitives::provider::chacha20poly1305::NONCE_LEN
        + LEN_MESSAGE_ID;
}
