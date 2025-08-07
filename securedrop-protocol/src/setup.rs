// Newsroom onboarding: Spec step 2
use messages::setup::{NewsroomSetupRequest, NewsroomSetupResponse};
// Journalist initial onboarding: Spec step 3.1
use messages::setup::{JournalistSetupRequest, JournalistSetupResponse};

impl NewsroomSetupRequest {
    /// Generate a new newsroom setup request.
    ///
    /// TODO: The caller (eventual CLI) should persist these keys to disk.
    pub fn new() -> Result<Self, Error> {
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
    pub fn new() -> Result<Self, Error> {
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
