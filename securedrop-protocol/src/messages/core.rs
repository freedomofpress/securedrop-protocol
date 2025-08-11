use crate::{Signature, VerifyingKey};

pub struct MessageBundle {}

/// Source fetches keys for the newsroom
///
/// This is the first request in step 5 of the spec.
pub struct SourceNewsroomKeyRequest {}

/// Newsroom returns their keys and proof of onboarding.
///
/// This is the first response in step 5 of the spec.
pub struct SourceNewsroomKeyResponse {
    newsroom_verifying_key: VerifyingKey,
    fpf_sig: Signature,
}
