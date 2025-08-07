use crate::sign::Signature;

/// This corresponds to step 2 in the spec
pub struct NewsroomSetupRequest {
    pub newsroom_verifying_key: VerifyingKey,
}

/// This corresponds to step 2 in the spec
pub struct NewsroomSetupResponse {
    /// A signature over the newsroom verifying key by the FPF signing key
    pub sig: Signature,
}
