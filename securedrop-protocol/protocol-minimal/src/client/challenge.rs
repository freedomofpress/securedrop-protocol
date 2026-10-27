use crate::challenge::{decrypt_message_id, derive_challenge_key};
use crate::keys::NR_ID;
use crate::primitives::ristretto255::dh_shared_secret;
use crate::{FetchResponse, UserSecret};
use alloc::vec::Vec;
use uuid::Uuid;

/// Solve fetch challenges (encrypted message IDs) and return array of valid message_ids.
/// TODO: For simplicity, serialize/deserialize is skipped
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn solve_fetch_challenges<S: UserSecret>(
    recipient: &S,
    challenges: &[FetchResponse],
) -> Vec<Uuid> {
    let mut message_ids: Vec<Uuid> = Vec::new();

    for chall in challenges.iter() {
        // Compute 3-party DH on the pmgdh
        let maybe_kmid_secret = dh_shared_secret(&chall.pmgdh, recipient.fetch_keypair().0);
        let challenge_key = derive_challenge_key(&maybe_kmid_secret, NR_ID).unwrap();

        // Try decrypting the encrypted message id
        // Convert to UUID (v4) format and add to message ID list on success
        match decrypt_message_id(&challenge_key, &chall.enc_id) {
            Ok(message_id_bytes) => {
                let uuid = crate::primitives::provider::uuid_parse::from_slice(&message_id_bytes);

                message_ids.push(uuid);
            }
            Err(_) => {
                // An error in decryption is fine (may not be a valid message_id), but
                // an error in uuid parsing isn't.
            }
        }
    }
    message_ids
}
