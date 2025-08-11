use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

// Newsroom onboarding: Spec step 2
use crate::messages::setup::{NewsroomSetupRequest, NewsroomSetupResponse};

impl NewsroomSetupRequest {
    /// Generate a new newsroom setup request.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn new<R: RngCore + CryptoRng>(_rng: R) -> Result<Self, Error> {
        unimplemented!()
    }

    /// Setup a newsroom. This corresponds to step 2 in the spec.
    ///
    /// This runs on FPF hardware.
    ///
    /// The generated newsroom verifying key is sent to FPF,
    /// which produces a signature over the newsroom verifying key using the
    /// FPF signing key.
    ///
    /// TODO: There is a manual verification step here, so the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    pub fn sign() -> Result<NewsroomSetupResponse, Error> {
        unimplemented!()
    }
}
