use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

use crate::{Signature, SigningKey, VerifyingKey};

// Newsroom onboarding: Spec step 2
use crate::messages::setup::{NewsroomSetupRequest, NewsroomSetupResponse};
// Journalist initial onboarding: Spec step 3.1
use crate::messages::setup::{JournalistSetupRequest, JournalistSetupResponse};
// Journalist key replenishment: Spec step 3.2
use crate::messages::setup::JournalistRefreshRequest;

impl NewsroomSetupRequest {
    /// Generate a new newsroom setup request.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, Error> {
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

impl JournalistSetupRequest {
    /// Generate a new journalist setup request.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, Error> {
        unimplemented!()
    }

    /// Setup a journalist. This corresponds to step 3.1 in the spec.
    ///
    /// This runs on newsroom hardware.
    ///
    /// The generated journalist keys are sent to the newsroom,
    /// which produces a signature over the bundle of journalist keys using
    /// the newsroom signing key.
    ///
    /// TODO: There is a manual verification step here, so the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    pub fn sign() -> Result<JournalistSetupResponse, Error> {
        unimplemented!()
    }
}

impl JournalistRefreshRequest {
    /// Generate a new refresh request. This involves generating some new keys and then
    /// signing them.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn new<R: RngCore + CryptoRng>(
        mut rng: R,
        signing_key: &SigningKey,
    ) -> Result<Self, Error> {
        unimplemented!()
    }

    /// Process a new refresh request from the journalist.
    ///
    /// This runs on the SecureDrop server.
    ///
    /// TODO: The caller should persist the keys for J.
    pub fn verify() -> Result<(), Error> {
        // TODO: Check signature
        unimplemented!()
    }
}
