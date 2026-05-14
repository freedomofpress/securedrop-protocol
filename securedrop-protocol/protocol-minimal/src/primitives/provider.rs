/// Import required crypto provider params.
/// Allows other modules to use crypto provider opaquely
///
pub mod params {
    pub mod curve25519 {
        pub const SK_LEN: usize = libcrux_curve25519::DK_LEN;
        pub const PK_LEN: usize = libcrux_curve25519::EK_LEN;
        pub use libcrux_curve25519::ecdh;
        pub(crate) const LEN_DHKEM_ENCAPS_KEY: usize = libcrux_curve25519::EK_LEN;
        pub(crate) const LEN_DHKEM_DECAPS_KEY: usize = libcrux_curve25519::DK_LEN;
        pub(crate) const LEN_DHKEM_SHAREDSECRET_ENCAPS: usize = libcrux_curve25519::SS_LEN;
        pub(crate) const LEN_DHKEM_SHARED_SECRET: usize = libcrux_curve25519::SS_LEN;
        pub const LEN_DH_ITEM: usize = LEN_DHKEM_DECAPS_KEY;
    }

    pub mod ed25519 {
        pub use libcrux_ed25519::{
            SigningKey as LibCruxSigningKey, VerificationKey as LibCruxVerifyingKey,
        };
    }

    pub mod kem {
        pub use libcrux_kem::{
            Algorithm, MlKem768, PrivateKey, PublicKey, key_gen, key_gen_derand,
        };
    }

    pub mod traits {
        pub use libcrux_traits::kem::arrayref::Kem as ArrayRefKem;
        pub use libcrux_traits::kem::owned::Kem as OwnedKem;
    }

    pub mod mlkem {
        pub const KEY_GENERATION_SEED_SIZE: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;
        pub use libcrux_ml_kem::mlkem768;
    }

    pub mod chacha20poly1305 {
        pub const KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;
        pub const NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;
        pub const TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;
        pub use libcrux_chacha20poly1305::{decrypt, encrypt};
    }
}
