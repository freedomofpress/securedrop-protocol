//! The setup steps included here are:
//! * Newsroom onboarding (step 2 in the spec),
//! * Journalist initial onboarding (step 3.1 in the spec),
//! * Journalist ephemeral key replenishment (step 3.2 in the spec).
//!
//! The FPF setup process (step 1 in the spec) and source initial setup (step 4 in the spec)
//! are both local only and do not involve any protocol messages.

use crate::primitives::DHPublicKey;
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
    pub verifying_key: VerifyingKey,
    pub fetch_pubkey: DHPublicKey,
    pub dh_pubkey: DHPublicKey,
}

/// Response from the newsroom to the journalist for initial onboarding.
///
/// Step 3.1 in the spec.
pub struct JournalistSetupResponse {
    /// A signature over the journalist verifying key by the newsroom signing key
    pub sig: Signature,
}

/// Request from the journalist to the SecureDrop server for key replenishment.
///
/// Step 3.2 in the spec.
pub struct JournalistRefreshRequest {
    pub verifying_key: VerifyingKey,
    pub fetch_pubkey: DHPublicKey,
    pub dh_pubkey: DHPublicKey,
    pub sig: Signature,
}
