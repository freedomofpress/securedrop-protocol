use messages::setup::{NewsroomSetupRequest, NewsroomSetupResponse};

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
/// then proceed.
impl NewsroomSetupRequest {
    pub fn sign() -> Result<NewsroomSetupResponse, Error> {
        unimplemented!()
    }
}
