mod journalist;
mod newsroom;
mod source;

use rand_core::{CryptoRng, RngCore};

use crate::{SigningKey, VerifyingKey};

/// A key pair for FPF.
///
/// TODO: Make the signing key private.
pub struct FPFKeyPair {
    pub sk: SigningKey,
    pub vk: VerifyingKey,
}

impl FPFKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> FPFKeyPair {
        let sk = SigningKey::new(&mut rng).unwrap();
        let vk = sk.vk;
        FPFKeyPair { sk, vk }
    }
}

pub use journalist::{
    JournalistDHKeyPair, JournalistEnrollmentKeyBundle, JournalistEnrollmentKeyBundle0_3,
    JournalistEphemeralDHKeyPair, JournalistEphemeralKEMKeyPair, JournalistEphemeralKeyBundle,
    JournalistEphemeralPKEKeyPair, JournalistEphemeralPublicKeys, JournalistFetchKeyPair,
    JournalistSigningKeyPair,
};
pub use newsroom::NewsroomKeyPair;
pub use source::{
    SourceDHKeyPair, SourceFetchKeyPair, SourceKEMKeyPair, SourceKeyBundle, SourcePKEKeyPair,
    SourcePassphrase, SourcePublicKeys,
};
