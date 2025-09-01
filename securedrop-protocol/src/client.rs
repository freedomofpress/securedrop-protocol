use crate::messages::core::{
    Message, MessageChallengeFetchRequest, MessageChallengeFetchResponse, MessageFetchResponse,
};
use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};
use uuid::Uuid;

/// Trait for structured messages that can be serialized for encryption
pub trait StructuredMessage {
    /// Serialize the message into bytes for padding and encryption
    fn into_bytes(self) -> Vec<u8>;
}

/// Internal trait for private key access - not to be exposed
pub(crate) trait ClientPrivate {
    /// Get the fetching private key for message ID decryption
    fn fetching_private_key(&self) -> Result<[u8; 32], Error>;
}

/// Common client functionality for source and journalist clients
pub trait Client {
    /// Associated type for the newsroom key
    type NewsroomKey;

    /// Get the newsroom's verifying key
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
            let q_public_key = crate::primitives::x25519::dh_public_key_from_scalar(
                q_i.clone().try_into().unwrap_or([0u8; 32]),
            );
            let k_i =
                crate::primitives::x25519::dh_shared_secret(&q_public_key, fetching_private_key)?
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

    /// Fetch a specific message (step 8)
    fn fetch_message(&self, _message_id: Uuid) -> Option<MessageFetchResponse> {
        unimplemented!("")
    }

    /// Submit a structured message (step 6 for sources, step 9 for journalists)
    ///
    /// This is a generic method that handles both source message submission and journalist replies.
    /// The specific message structure and encryption details are provided by the implementing types.
    fn submit_structured_message<M, R>(
        &self,
        message: M,
        recipient_ephemeral_keys: (
            &crate::primitives::x25519::DHPublicKey,
            &crate::primitives::PPKPublicKey,
        ),
        recipient_pke_key: &crate::primitives::PPKPublicKey,
        recipient_fetch_key: &crate::primitives::x25519::DHPublicKey,
        sender_dh_private_key: &crate::primitives::x25519::DHPrivateKey,
        sender_dh_public_key: &crate::primitives::x25519::DHPublicKey,
        rng: &mut R,
    ) -> Result<Message, Error>
    where
        M: StructuredMessage,
        R: RngCore + CryptoRng,
    {
        // 1. Create the padded message
        let padded_message = crate::primitives::pad::pad_message(&message.into_bytes());

        // 2. Perform authenticated encryption
        let ((c1, c2), c_double_prime) = crate::primitives::auth_encrypt(
            sender_dh_private_key,
            recipient_ephemeral_keys,
            &padded_message,
        )?;

        // 3. Encrypt the DH key and ciphertexts
        let c_prime = crate::primitives::enc(recipient_pke_key, sender_dh_public_key, &c1, &c2)?;

        // 4. Combine ciphertexts
        let ciphertext = [c_prime, c_double_prime].concat();

        // 5. Generate DH shares for message ID encryption
        let x_bytes = crate::primitives::x25519::generate_random_scalar(rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate random scalar: {}", e))?;
        let x_share = crate::primitives::x25519::dh_public_key_from_scalar(x_bytes);
        let z_share = crate::primitives::x25519::dh_shared_secret(recipient_fetch_key, x_bytes)?;

        // 6. Create message submit request
        let request = Message {
            ciphertext,
            dh_share_z: z_share.into_bytes().to_vec(),
            dh_share_x: x_share.into_bytes().to_vec(),
        };

        Ok(request)
    }
}
