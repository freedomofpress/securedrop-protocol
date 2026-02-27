use alloc::vec::Vec;
use anyhow::Error;
use getrandom;

// Later: Can make these all pub(crate)
pub mod dh_akem;
pub mod mlkem;
pub mod pad;
pub mod x25519;
pub mod xwing;

pub use crate::primitives::dh_akem::generate_dh_akem_keypair;
pub use crate::primitives::mlkem::generate_mlkem768_keypair;
pub use crate::primitives::xwing::generate_xwing_keypair;

/// Fixed number of message ID entries to return in privacy-preserving fetch
///
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
pub const MESSAGE_ID_FETCH_SIZE: usize = 10;

// TODO: aesgcm256 for consistency with other methods
/// Symmetric encryption for message IDs using ChaCha20-Poly1305
///
/// This is used in step 7 for encrypting message IDs with a shared secret
pub fn encrypt_message_id(key: &[u8], message_id: &[u8]) -> Result<Vec<u8>, Error> {
    use libcrux_chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN};

    if key.len() != KEY_LEN {
        return Err(anyhow::anyhow!("Invalid key length"));
    }

    // Generate a random nonce (use getrandom for cross target compatibility)
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("Need randomness");

    // Prepare output buffer: nonce + ciphertext + tag
    let mut output = alloc::vec::Vec::new();
    output.extend_from_slice(&nonce);

    let mut ciphertext = alloc::vec![0u8; message_id.len() + TAG_LEN];
    let key_array: [u8; KEY_LEN] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Key length mismatch"))?;

    // Encrypt the message ID
    libcrux_chacha20poly1305::encrypt(
        &key_array,
        message_id,
        &mut ciphertext,
        &[], // empty AAD
        &nonce,
    )
    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {:?}", e))?;

    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Symmetric decryption for message IDs using ChaCha20-Poly1305
///
/// This is used in step 7 for decrypting message IDs with a shared secret
pub fn decrypt_message_id(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
    use libcrux_chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN};

    if key.len() != KEY_LEN {
        return Err(anyhow::anyhow!("Invalid key length"));
    }

    if encrypted_data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow::anyhow!("Encrypted data too short"));
    }

    // Extract nonce and ciphertext
    let nonce: [u8; NONCE_LEN] = encrypted_data[..NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Nonce extraction failed"))?;
    let ciphertext = &encrypted_data[NONCE_LEN..];

    // Prepare output buffer
    let mut plaintext = alloc::vec![0u8; ciphertext.len() - TAG_LEN];
    let key_array: [u8; KEY_LEN] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Key length mismatch"))?;

    // Decrypt the message ID
    libcrux_chacha20poly1305::decrypt(
        &key_array,
        &mut plaintext,
        ciphertext,
        &[], // empty AAD
        &nonce,
    )
    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {:?}", e))?;

    Ok(plaintext)
}
