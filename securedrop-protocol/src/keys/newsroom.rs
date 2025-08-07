use crate::sign::{SigningKey, VerifyingKey};

/// Newsroom keypair used for signing.
struct NewsroomKeyPair {
    pub(crate) vk: VerifyingKey,
    sk: SigningKey,
}
