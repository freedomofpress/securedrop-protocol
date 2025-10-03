use alloc::vec::Vec;
use anyhow::Error;
use getrandom;
use hpke_rs::{
    Hpke,
    hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    libcrux,
    prelude::HpkeMode,
};
use libcrux_traits::kem::arrayref::Kem;

// Later: Can make these all pub(crate)
pub mod dh_akem;
pub mod mlkem;
pub mod pad;
pub mod x25519;
pub mod xwing;

pub use crate::primitives::dh_akem::generate_dh_akem_keypair;
pub use crate::primitives::mlkem::generate_mlkem768_keypair;
use crate::primitives::x25519::{DHPrivateKey, DHPublicKey};
pub use crate::primitives::xwing::generate_xwing_keypair;

/// Fixed number of message ID entries to return in privacy-preserving fetch
///
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
pub const MESSAGE_ID_FETCH_SIZE: usize = 10;

/// Everything below here is 0.2 and will be updated / moved to the appropriate module

// temp: use proper type
#[derive(Debug, Clone)]
pub struct PPKPrivateKey(DHPrivateKey);

#[derive(Debug, Clone)]
pub struct PPKPublicKey(DHPublicKey);

impl PPKPublicKey {
    pub fn new(public_key: DHPublicKey) -> Self {
        Self(public_key)
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(DHPublicKey::from_bytes(bytes))
    }
}

impl PPKPrivateKey {
    pub fn new(private_key: DHPrivateKey) -> Self {
        Self(private_key)
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(DHPrivateKey::from_bytes(bytes))
    }
}

/// Authenticated encryption according to the SecureDrop protocol using HPKE
///
/// This implements HPKE AuthEnc mode as specified in the SecureDrop protocol
/// using the source's DH private key and journalist's ephemeral keys
///
/// TODO: Horrible types in return value
pub fn auth_encrypt(
    source_dh_sk: &DHPrivateKey,
    journalist_ephemeral_keys: (&DHPublicKey, &PPKPublicKey),
    message: &[u8],
) -> Result<((Vec<u8>, Vec<u8>), Vec<u8>), Error> {
    // TODO: Update these based on primitive choices in final spec
    // Note: We need to specify the crypto backend - using libcrux for consistency
    let mut hpke: Hpke<libcrux::HpkeLibcrux> = Hpke::new(
        HpkeMode::Auth,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    );

    // Convert our key types to HPKE key types
    // TODO: Need to use these HPKE types in the keys module
    // For now, using placeholder keys
    let sender_private_key =
        hpke_rs::HpkePrivateKey::new(source_dh_sk.clone().into_bytes().to_vec());

    // Need to also incorporate J_{ekem} here, mumble mumble something about PQ KEM
    let recipient_public_key =
        hpke_rs::HpkePublicKey::new(journalist_ephemeral_keys.0.clone().into_bytes().to_vec());

    // Use HPKE seal for authenticated encryption
    let (encapsulated_key, ciphertext) = hpke
        .seal(
            &recipient_public_key,     // pk_r: recipient's public key
            &[],                       // info: empty for now
            &[],                       // aad: empty for now (ε in the spec)
            message,                   // plain_txt: the message to encrypt
            None,                      // psk: no pre-shared key
            None,                      // psk_id: no PSK ID
            Some(&sender_private_key), // sk_s: sender's private key for authentication
        )
        .map_err(|e| anyhow::anyhow!("HPKE seal failed: {:?}", e))?;

    // Split the encapsulated key into c1 and c2 components
    // TODO: This is a placeholder
    let c1 = if encapsulated_key.len() >= 32 {
        encapsulated_key[..32].to_vec()
    } else {
        encapsulated_key.clone()
    };

    let c2 = if encapsulated_key.len() > 32 {
        encapsulated_key[32..].to_vec()
    } else {
        Vec::new()
    };

    Ok(((c1, c2), ciphertext))
}

/// This implements HPKE Base mode (unauthenticated) for metadata encryption
///
/// TODO: Check this is correct
pub fn enc(
    journalist_epke_pk: &PPKPublicKey,
    source_dh_pk: &DHPublicKey,
    c1: &[u8],
    c2: &[u8],
) -> Result<Vec<u8>, Error> {
    // Create HPKE configuration for Base mode (unauthenticated)
    let mut hpke: Hpke<libcrux::HpkeLibcrux> = Hpke::new(
        HpkeMode::Base, // Base mode for unauthenticated encryption
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    );

    // Convert recipient public key to HPKE format
    let recipient_public_key =
        hpke_rs::HpkePublicKey::new(journalist_epke_pk.clone().into_bytes().to_vec());

    // Prepare metadata: S_dh,pk || c_1 || c_2
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&source_dh_pk.clone().into_bytes());
    metadata.extend_from_slice(c1);
    metadata.extend_from_slice(c2);

    // Setup sender (key encapsulation) in Base mode
    let (encapsulated_key, mut context) = hpke
        .setup_sender(
            &recipient_public_key, // J^i_epke,pk
            &[],                   // info: empty
            None,                  // psk: no pre-shared key
            None,                  // psk_id: no PSK ID
            None,                  // sk_s: no sender private key (Base mode)
        )
        .map_err(|e| anyhow::anyhow!("HPKE setup_sender failed: {:?}", e))?;

    // Encrypt the metadata using the derived context
    let encrypted_metadata = context
        .seal(
            &[],       // aad: empty
            &metadata, // S_dh,pk || c_1 || c_2
        )
        .map_err(|e| anyhow::anyhow!("HPKE context.seal failed: {:?}", e))?;

    // Return encapsulated_key || encrypted_metadata
    let mut result = Vec::new();
    result.extend_from_slice(&encapsulated_key);
    result.extend_from_slice(&encrypted_metadata);

    Ok(result)
}

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
