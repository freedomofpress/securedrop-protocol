/// Import required crypto provider params.
/// Allows other modules to use crypto provider opaquely
///
pub mod curve25519 {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const SK_LEN: usize = libcrux_curve25519::DK_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const PK_LEN: usize = libcrux_curve25519::EK_LEN;

    pub(crate) const LEN_DH_SHARE: usize = libcrux_curve25519::SS_LEN;
    pub(crate) use libcrux_curve25519::ecdh;
}

pub mod ed25519 {

    pub(crate) use libcrux_ed25519::{
        SigningKey as LibCruxSigningKey, VerificationKey as LibCruxVerifyingKey,
    };
}

pub mod kem {

    pub(crate) use libcrux_kem::{
        Algorithm, MlKem768, PrivateKey, PublicKey, key_gen, key_gen_derand,
    };
}

pub mod traits {

    pub(crate) use libcrux_traits::kem::arrayref::Kem as ArrayRefKem;

    pub(crate) use libcrux_traits::kem::owned::Kem as OwnedKem;
}

pub mod mlkem {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const KEY_GENERATION_SEED_SIZE: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;

    pub(crate) use libcrux_ml_kem::mlkem768;
}

#[cfg_attr(hax, hax_lib::opaque)]
pub mod chacha20poly1305 {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;

    pub(crate) use libcrux_chacha20poly1305::{decrypt, encrypt};
}

pub mod hpke_rs {
    pub(crate) use hpke_rs::{
        Hpke, HpkePrivateKey, HpkePublicKey, Mode, hpke_types::AeadAlgorithm::Aes256Gcm,
        hpke_types::KdfAlgorithm::HkdfSha256, hpke_types::KemAlgorithm::DhKem25519,
        hpke_types::KemAlgorithm::XWingDraft06, libcrux::HpkeLibcrux,
    };
}

pub mod constants {

    // Message ID (uuid) and KMID
    pub(crate) const LEN_MESSAGE_ID: usize = 16;
    // TODO: this will be aes-gcm and use AES GCM TagSize
    // TODO: current implementation prepends the nonce to the encrypted message.
    // Recheck this when switching implementations.
    pub(crate) const LEN_KMID: usize = crate::primitives::provider::chacha20poly1305::TAG_LEN
        + crate::primitives::provider::chacha20poly1305::NONCE_LEN
        + LEN_MESSAGE_ID;
}
