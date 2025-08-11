use crate::sign::{SigningKey, VerifyingKey};

/// Newsroom keypair used for signing.
#[derive(Clone)]
pub struct NewsroomKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}
