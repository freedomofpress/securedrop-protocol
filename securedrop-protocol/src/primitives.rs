use alloc::vec::Vec;
use anyhow::Error;
use hpke_rs::{
    Hpke,
    hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    libcrux,
    prelude::HpkeMode,
};
use libcrux_curve25519::{DK_LEN as SK_LEN, EK_LEN as PK_LEN};
use libcrux_traits::kem::arrayref::Kem;
use rand_core::{CryptoRng, RngCore};

/// Fixed-length padded message length.
///
/// Note: I made this up. We should pick something based on actual reasons.
pub const PADDED_MESSAGE_LEN: usize = 1024;

/// Fixed number of message ID entries to return in privacy-preserving fetch
///
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
pub const MESSAGE_ID_FETCH_SIZE: usize = 10;

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

    pub fn from_bytes(bytes: [u8; PK_LEN]) -> Self {
        Self(DHPublicKey::from_bytes(bytes))
    }
}

impl PPKPrivateKey {
    pub fn new(private_key: DHPrivateKey) -> Self {
        Self(private_key)
    }

    pub fn into_bytes(self) -> [u8; SK_LEN] {
        self.0.into_bytes()
    }

    pub fn from_bytes(bytes: [u8; SK_LEN]) -> Self {
        Self(DHPrivateKey::from_bytes(bytes))
    }
}

#[derive(Debug, Clone)]
pub struct DHPublicKey([u8; PK_LEN]);

impl DHPublicKey {
    pub fn into_bytes(self) -> [u8; PK_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; PK_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone)]
pub struct DHPrivateKey([u8; SK_LEN]);

impl DHPrivateKey {
    pub fn into_bytes(self) -> [u8; SK_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; SK_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone)]
pub struct DHSharedSecret([u8; 32]);

impl DHSharedSecret {
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Generate a new DH key pair using X25519
pub fn generate_dh_keypair<R: RngCore + CryptoRng>(
    mut rng: R,
) -> Result<(DHPrivateKey, DHPublicKey), Error> {
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);

    let mut public_key = [0u8; PK_LEN];
    let mut secret_key = [0u8; SK_LEN];

    // Generate the key pair using X25519 from libcrux
    // Parameters: ek (public key), dk (secret key), rand (randomness)
    libcrux_curve25519::X25519::keygen(&mut public_key, &mut secret_key, &randomness)
        .map_err(|_| anyhow::anyhow!("X25519 key generation failed"))?;

    Ok((DHPrivateKey(secret_key), DHPublicKey(public_key)))
}

/// Generate a random scalar for DH operations using X25519
pub fn generate_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Result<[u8; 32], Error> {
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);

    let mut secret_key = [0u8; 32];
    let mut _public_key = [0u8; 32]; // We don't need the public key here

    // Generate the key pair using X25519 from libcrux
    // Parameters: ek (public key), dk (secret key), rand (randomness)
    libcrux_curve25519::X25519::keygen(&mut _public_key, &mut secret_key, &randomness)
        .map_err(|_| anyhow::anyhow!("X25519 key generation failed"))?;

    Ok(secret_key)
}

/// Convert a scalar to a DH public key using the X25519 standard generator base point
///
/// libcrux_curve25519::secret_to_public uses the standard X25519 base point G = 9
/// (defined as [9, 0, 0, 0, ...] in the HACL implementation, see `g25519` in their code)
pub fn dh_public_key_from_scalar(scalar: [u8; 32]) -> DHPublicKey {
    let mut public_key_bytes = [0u8; 32];
    libcrux_curve25519::secret_to_public(&mut public_key_bytes, &scalar);
    DHPublicKey::from_bytes(public_key_bytes)
}

/// Compute DH shared secret
pub fn dh_shared_secret(public_key: &DHPublicKey, private_scalar: [u8; 32]) -> DHSharedSecret {
    let mut shared_secret_bytes = [0u8; 32];
    libcrux_curve25519::ecdh(&mut shared_secret_bytes, &private_scalar, &public_key.0);
    DHSharedSecret(shared_secret_bytes)
}

/// Pad a message to a fixed length
pub fn pad_message(message: &[u8]) -> Vec<u8> {
    if message.len() > PADDED_MESSAGE_LEN {
        // TODO: Handle message truncation or error outside of this function
        panic!("Message too long for padding");
    }

    let mut padded = Vec::with_capacity(PADDED_MESSAGE_LEN);
    padded.extend_from_slice(message);

    // Pad with zeros to reach the fixed length
    let padding_needed = PADDED_MESSAGE_LEN - message.len();
    for _ in 0..padding_needed {
        padded.push(0u8);
    }

    padded
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

    // Generate a random nonce
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

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
