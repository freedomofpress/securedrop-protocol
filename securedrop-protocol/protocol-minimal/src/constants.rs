// Key lengths
pub(crate) const LEN_DHKEM_ENCAPS_KEY: usize = libcrux_curve25519::EK_LEN;
pub(crate) const LEN_DHKEM_DECAPS_KEY: usize = libcrux_curve25519::DK_LEN;
pub(crate) const LEN_DHKEM_SHAREDSECRET_ENCAPS: usize = libcrux_curve25519::SS_LEN;
pub(crate) const LEN_DHKEM_SHARED_SECRET: usize = libcrux_curve25519::SS_LEN;
pub const LEN_DH_ITEM: usize = LEN_DHKEM_DECAPS_KEY;

// https://openquantumsafe.org/liboqs/algorithms/kem/ml-kem.html
// todo, source from crates instead of hardcoding
pub const LEN_MLKEM_ENCAPS_KEY: usize = 1184;
pub(crate) const LEN_MLKEM_DECAPS_KEY: usize = 2400;
pub(crate) const LEN_MLKEM_SHAREDSECRET_ENCAPS: usize = 1088;
pub(crate) const LEN_MLKEM_SHAREDSECRET: usize = 32;
pub(crate) const LEN_MLKEM_RAND_SEED_SIZE: usize = 64;

// https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/#name-encoding-and-sizes
pub const LEN_XWING_ENCAPS_KEY: usize = 1216;
pub(crate) const LEN_XWING_DECAPS_KEY: usize = 32;
pub(crate) const LEN_XWING_SHAREDSECRET_ENCAPS: usize = 1120;
pub(crate) const LEN_XWING_SHAREDSECRET: usize = 32;
pub(crate) const LEN_XWING_RAND_SEED_SIZE: usize = 96;

// Message ID (uuid) and KMID
pub(crate) const LEN_MESSAGE_ID: usize = 16;
// TODO: this will be aes-gcm and use AES GCM TagSize
// TODO: current implementation prepends the nonce to the encrypted message.
// Recheck this when switching implementations.
pub(crate) const LEN_KMID: usize =
    libcrux_chacha20poly1305::TAG_LEN + libcrux_chacha20poly1305::NONCE_LEN + LEN_MESSAGE_ID;
