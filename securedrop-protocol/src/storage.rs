use collections::HashMap;

use crate::sign::{Signature, VerifyingKey};
use crate::MessageBundle;

pub struct ServerStorage {
    /// Newsroom verifying key
    newsroom_vk: VerifyingKey,
    /// Signature demonstrating onboarding
    fpf_sig: Signature,
    /// Journalists with their long term keys
    journalists: HashMap<u64, (VerifyingKey, DHPublicKey, DHPublicKey, Signature)>,
    /// Journalists ephmeral keystore
    //TODO
    /// Store of messages
    messages: HashMap<u64, MessageBundle>,
}

impl ServerStorage {
    // TODO: Rename
    pub fn keys(self) -> (VerifyingKey, Signature) {
        (self.newsroom_vk, self.fpf_sig)
    }
}
