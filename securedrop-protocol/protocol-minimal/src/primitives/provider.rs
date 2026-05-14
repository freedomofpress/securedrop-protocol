/// Import required crypto provider params.
/// Allows other modules to use crypto provider opaquely
///
pub mod params {

    pub mod curve25519 {

        #[cfg_attr(hax, hax_lib::opaque)]
        pub const SK_LEN: usize = libcrux_curve25519::DK_LEN;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub const PK_LEN: usize = libcrux_curve25519::EK_LEN;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_curve25519::ecdh;
    }

    pub mod ed25519 {

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_ed25519::{
            SigningKey as LibCruxSigningKey, VerificationKey as LibCruxVerifyingKey,
        };
    }

    pub mod kem {

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_kem::{
            Algorithm, MlKem768, PrivateKey, PublicKey, key_gen, key_gen_derand,
        };
    }

    pub mod traits {

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_traits::kem::arrayref::Kem as ArrayRefKem;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_traits::kem::owned::Kem as OwnedKem;
    }

    pub mod mlkem {

        #[cfg_attr(hax, hax_lib::opaque)]
        pub const KEY_GENERATION_SEED_SIZE: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_ml_kem::mlkem768;
    }

    #[cfg_attr(hax, hax_lib::opaque)]
    pub mod chacha20poly1305 {

        #[cfg_attr(hax, hax_lib::opaque)]
        pub const KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub const NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub const TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;

        #[cfg_attr(hax, hax_lib::opaque)]
        pub use libcrux_chacha20poly1305::{decrypt, encrypt};
    }
}
