use crate::messages::core::{MessageChallengeFetchRequest, MessageChallengeFetchResponse};
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

/// Internal trait for private key access - not to be exposed
pub(crate) trait ClientPrivate {
    /// Get the fetching private key for message ID decryption
    fn fetching_private_key(&self) -> Result<[u8; 32], Error>;
}

/// Common client functionality for source and journalist clients
pub trait Client {
    /// Associated type for the newsroom key
    type NewsroomKey;

    /// Get the newsroom's verifying key (optional access)
    fn newsroom_verifying_key(&self) -> Option<&Self::NewsroomKey>;

    /// Store the newsroom's verifying key
    fn set_newsroom_verifying_key(&mut self, key: Self::NewsroomKey);

    /// Get the newsroom's verifying key, returning an error if not available
    fn get_newsroom_verifying_key(&self) -> Result<&Self::NewsroomKey, Error> {
        self.newsroom_verifying_key()
            .ok_or_else(|| anyhow::anyhow!("Newsroom verifying key not available"))
    }

    /// Fetch message IDs (step 7)
    fn fetch_message_ids<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> MessageChallengeFetchRequest;

    /// Process message ID fetch response (step 7)
    fn process_message_id_response(
        &self,
        response: &MessageChallengeFetchResponse,
    ) -> Result<Vec<Uuid>, Error>
    where
        Self: ClientPrivate,
    {
        let mut message_ids = Vec::new();
        let fetching_private_key = self.fetching_private_key()?;

        // Process each (Q_i, cid_i) pair
        for (q_i, cid_i) in &response.messages {
            // k_i = DH(Q_i, U_fetch,sk)
            let q_public_key = crate::primitives::dh_public_key_from_scalar(
                q_i.clone().try_into().unwrap_or([0u8; 32]),
            );
            let k_i = crate::primitives::dh_shared_secret(&q_public_key, fetching_private_key)
                .into_bytes();

            // Decrypt message ID: id_i = Dec(k_i, cid_i)
            match crate::primitives::decrypt_message_id(&k_i, cid_i) {
                Ok(decrypted_id) => {
                    // Try to parse as UUID
                    if decrypted_id.len() == 16 {
                        if let Ok(id_bytes) = decrypted_id.try_into() {
                            let uuid = Uuid::from_bytes(id_bytes);
                            message_ids.push(uuid);
                        }
                    }
                }
                Err(_) => {
                    // Decryption failed, this is a random entry
                }
            }
        }

        Ok(message_ids)
    }
}
