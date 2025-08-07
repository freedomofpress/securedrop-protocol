mod journalist;
mod newsroom;
mod source;

use rand_core::{CryptoRng, RngCore};

use crate::{SigningKey, VerifyingKey};

pub struct FPFKeyPair {
    pub sk: SigningKey,
    pub(crate) vk: VerifyingKey,
}

impl FPFKeyPair {
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> FPFKeyPair {
        unimplemented!()
    }
}

pub use journalist::{
    JournalistDHKeyPair, JournalistEphemeralDHKeyPair, JournalistEphemeralKEMKeyPair,
    JournalistEphemeralPKEKeyPair, JournalistFetchKeyPair, JournalistSigningKeypair,
};
pub use newsroom::NewsroomKeyPair;
pub use source::{SourceDHKeyPair, SourceFetchKeyPair, SourceFetchKeyPair, SourceKEMKeyPair};
