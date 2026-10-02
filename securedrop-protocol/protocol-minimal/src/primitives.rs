use alloc::vec::Vec;
use anyhow::Error;
use rand_core::{CryptoRng, RngCore};

pub(crate) mod dh_akem;
pub(crate) mod mlkem;
pub mod pad;
pub(crate) mod provider;
pub mod ristretto255;
pub(crate) mod xwing;

use provider::chacha20poly1305::KEY_LEN;

use crate::primitives::ristretto255::DHPublicKey;

/// Fixed number of message ID entries to return in privacy-preserving fetch
///
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
pub const MESSAGE_ID_FETCH_SIZE: usize = 10;

/// Fixed, public salt for challenge id encryption.
const CHALLENGE_SALT: &[u8] = b"securedrop-challenge-v1";

/// Derive symmetric key used for ChaCha20-Poly1305 challenge encryption
///
/// This is used in step 7 for encrypting message IDs with a shared secret
///
pub fn derive_challenge_key(
    shared_secret: &DHPublicKey,
    newsroom_id: &[u8],
) -> Result<[u8; KEY_LEN], Error> {
    use crate::primitives::provider::hkdf;

    let mut challenge_key: [u8; KEY_LEN] = [0u8; KEY_LEN];
    // Key is KDF(shared_secret, newsroom_id)
    hkdf::sha256(
        &mut challenge_key,
        CHALLENGE_SALT,
        &shared_secret.into_bytes(),
        newsroom_id,
    )
    .map_err(|_| anyhow::anyhow!("HKDF challenge key derivation failed"))?;

    Ok(challenge_key)
}

/// Symmetric encryption for message IDs using ChaCha20-Poly1305
///
/// This is used in step 7 for encrypting message IDs with a shared secret
///
#[cfg_attr(hax, hax_lib::requires(
    message_id.len()
        <= usize::MAX
            - provider::chacha20poly1305::NONCE_LEN
            - provider::chacha20poly1305::TAG_LEN
))]
pub fn encrypt_message_id(key: &[u8; KEY_LEN], message_id: &[u8]) -> Result<Vec<u8>, Error> {
    use provider::chacha20poly1305::{NONCE_LEN, TAG_LEN};

    // Use a zero-filled nonce
    let nonce = [0u8; NONCE_LEN];

    // Prepare output buffer: ciphertext + tag
    let mut output = alloc::vec::Vec::new();
    let mut ciphertext = alloc::vec![0u8; message_id.len() + TAG_LEN];

    // Encrypt the message ID
    match provider::chacha20poly1305::encrypt(key, message_id, &mut ciphertext, &[], &nonce) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!(
                "ChaCha20-Poly1305 encryption failed: {:?}",
                e
            ));
        }
    }
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Symmetric decryption for message IDs using ChaCha20-Poly1305
///
/// This is used in step 7 for decrypting message IDs with a shared secret
pub fn decrypt_message_id(key: &[u8; KEY_LEN], encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
    use provider::chacha20poly1305::{NONCE_LEN, TAG_LEN};

    if encrypted_data.len() < TAG_LEN {
        return Err(anyhow::anyhow!("Encrypted data too short"));
    }

    // Decrypt ciphertext with zero-filled nonce
    let nonce = [0u8; NONCE_LEN];

    // Prepare output buffer
    let mut plaintext = alloc::vec![0u8; encrypted_data.len() - TAG_LEN];

    // Decrypt the message ID
    provider::chacha20poly1305::decrypt(
        key,
        &mut plaintext,
        encrypted_data,
        &[], // empty AAD
        &nonce,
    )
    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {:?}", e))?;

    Ok(plaintext)
}
