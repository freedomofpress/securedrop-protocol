//! The setup steps included here are:
//! * Newsroom onboarding (step 2 in the spec),
//! * Journalist initial onboarding (step 3.1 in the spec),
//! * Journalist ephemeral key replenishment (step 3.2 in the spec).
//!
//! The FPF setup process (step 1 in the spec) and source initial setup (step 4 in the spec)
//! are both local only and do not involve any protocol messages.

use crate::keys::{JournalistEnrollmentKeyBundle, JournalistOneTimeKeyBundle};
use crate::{Signature, VerifyingKey};

/// Request from the newsroom to FPF for verification.
///
/// Step 2 in the spec.
pub struct NewsroomSetupRequest {
    pub newsroom_verifying_key: VerifyingKey,
}

/// Response from FPF to the newsroom.
///
/// Step 2 in the spec.
pub struct NewsroomSetupResponse {
    /// A signature over the newsroom verifying key by the FPF signing key
    pub sig: Signature,
}

/// Request from the journalist to the newsroom for initial onboarding.
///
/// Step 3.1 in the spec.
pub struct JournalistSetupRequest {
    pub enrollment_key_bundle: JournalistEnrollmentKeyBundle,
}

/// Response from the newsroom to the journalist for initial onboarding.
///
/// Step 3.1 in the spec.
pub struct JournalistSetupResponse {
    /// A signature over the journalist enrollment bundle by the newsroom signing key
    pub sig: Signature,
}

/// Request from the journalist to the SecureDrop server for ephemeral key replenishment.
///
/// Step 3.2 in the spec.
pub struct JournalistRefreshRequest {
    /// Journalist's verifying key for identification
    ///
    /// NOTE: Not in spec, for discussion
    pub journalist_verifying_key: VerifyingKey,
    /// Bundle containing the journalist's ephemeral keys and signature
    pub ephemeral_key_bundle: JournalistOneTimeKeyBundle,
}

/// Response from the server to the journalist for ephemeral key replenishment.
///
/// Step 3.2 in the spec.
pub struct JournalistRefreshResponse {
    /// Acknowledgment that the ephemeral keys were stored
    pub success: bool,
}
