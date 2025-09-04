use alloc::vec::Vec;
use anyhow::Error;
use getrandom;
use hpke_rs::{
    Hpke,
    hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    libcrux,
    prelude::HpkeMode,
};
use libcrux_kem::{self, MlKem768};
use libcrux_ml_kem::mlkem768;
use libcrux_traits::kem::arrayref::Kem;

// Later: Can make these all pub(crate)
pub mod dh_akem;
pub mod mlkem;
pub mod pad;
pub mod x25519;
pub mod xwing;

pub use crate::primitives::dh_akem::generate_dh_akem_keypair;
pub use crate::primitives::mlkem::generate_mlkem768_keypair;
pub use crate::primitives::xwing::generate_xwing_keypair;
use crate::primitives::{
    dh_akem::{DhAkemPrivateKey, DhAkemPublicKey},
    mlkem::MLKEM768PublicKey,
    x25519::{DHPrivateKey, DHPublicKey},
    xwing::XWingPublicKey,
};

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

/// This implements HPKE AuthEnc with a PSK mode as specified in the SecureDrop protocol
/// using the sender's DH-AKEM private key and the recipient's DH-AKEM pubkey
/// and PQ KEM PSK pubkey.
///
/// TODO: One-shot hpke API
/// TODO: Horrible types in return value
pub fn auth_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    sender_dhakem_sk: &DhAkemPrivateKey,
    recipient_message_keys: (&DhAkemPublicKey, &MLKEM768PublicKey),
    message: &[u8],
) -> Result<((Vec<u8>, Vec<u8>), Vec<u8>), Error> {
    let mut hpke: Hpke<libcrux::HpkeLibcrux> = Hpke::new(
        HpkeMode::AuthPsk,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    );

    // Convert our key types to HPKE key types
    // TODO: Need to use these HPKE types in the keys module
    // For now, using placeholder keys
    let sender_private_key =
        hpke_rs::HpkePrivateKey::new(sender_dhakem_sk.clone().as_bytes().to_vec());

    // Recipient pubkeys for message encryption + PSK
    let recipient_public_key =
        hpke_rs::HpkePublicKey::new(recipient_message_keys.0.clone().as_bytes().to_vec());
    let recipient_pq_psk_key =
        mlkem768::MlKem768PublicKey::try_from(recipient_message_keys.1.clone().as_bytes())
            .expect("Expected mlkem768 pubkey");

    // Build PSK
    let mut rand_seed = [0u8; 32];
    rng.fill_bytes(&mut rand_seed);
    let (psk_ct, shared_secret) = mlkem768::encapsulate(&recipient_pq_psk_key, rand_seed);
    let fixed_psk_id = b"PSK_ID"; // TODO

    // Use HPKE SealAuth for authenticated encryption
    let (encapsulated_key, ciphertext) = hpke
        .seal(
            &recipient_public_key,     // pk_r: recipient's public key
            &[],                       // info: empty for now
            &[],                       // aad: empty for now (ε in the spec)
            message,                   // plain_txt: the message to encrypt
            Some(&shared_secret),      // psk: PQ shared secret
            Some(fixed_psk_id),        // psk_id: Fixed PSK ID required by spec (TODO)
            Some(&sender_private_key), // sk_s: sender's private key for authentication
        )
        .map_err(|e| anyhow::anyhow!("HPKE seal failed: {:?}", e))?;

    Ok(((psk_ct.as_slice().to_vec(), encapsulated_key), ciphertext))
}

/// This implements HPKE Base mode (unauthenticated) for metadata encryption
///
/// Encrypt the sender DH-AKEM pubkey to the recipient metadata pubkey/encaps key
/// using HPKE.Base mode.
/// The sender's other keys are included inside the authenticated ciphertext.
/// This key is required to open the authenticated ciphertext.
/// TODO: Use single-shot HPKE API instead of managing context
pub fn enc(
    receipient_md_pk: &XWingPublicKey,
    sender_dhakem_pk: &DhAkemPublicKey,
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
        hpke_rs::HpkePublicKey::new(receipient_md_pk.clone().as_bytes().to_vec());

    // Prepare metadata: S_dh,pk || c_1 || c_2
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&sender_dhakem_pk.as_bytes().clone());
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
