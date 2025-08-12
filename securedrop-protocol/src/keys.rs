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
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> FPFKeyPair {
        unimplemented!()
    }
}

pub use journalist::{
    JournalistDHKeyPair, JournalistEphemeralDHKeyPair, JournalistEphemeralKEMKeyPair,
    JournalistEphemeralKeyBundle, JournalistEphemeralPKEKeyPair, JournalistFetchKeyPair,
    JournalistSigningKeyPair,
};
pub use newsroom::NewsroomKeyPair;
pub use source::{SourceDHKeyPair, SourceFetchKeyPair, SourceKEMKeyPair, SourcePKEKeyPair};

// TODO: Define User trait that provides methods for keys shared between source and journalist?
// AND provides the handle methods
