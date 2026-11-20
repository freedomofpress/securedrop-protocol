use crate::keys::NR_ID;
use crate::message::MessagePublicKey;
use crate::metadata;
use crate::primitives::provider::constants::{LEN_KMID, LEN_MESSAGE_ID};
use crate::primitives::ristretto255::{
    DHPublicKey, dh_shared_secret, generate_dh_keypair, generate_random_scalar,
    random_dh_public_key,
};
use crate::{Envelope, FetchResponse, MessageKeyBundle, Plaintext, UserPublic, UserSecret};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

/// Error types returned by decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptError {
    /// No key bundle decrypts ct^PKE
    NoDecryptingKeyBundle,
    /// ct^PKE decrypted, but not to a valid pk_S^APKE
    InvalidSenderKey,
    /// SD-APKE.AuthDec failed either authentication or decryption
    AuthDecFailed,
    /// SD-APKE.AuthDec succeeded, but the plaintext was malformed
    MalformedPlaintext,
}

#[cfg_attr(hax, hax_lib::exclude)]
impl core::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecryptError::NoDecryptingKeyBundle => {
                write!(f, "no key bundle could decrypt the metadata")
            }
            DecryptError::InvalidSenderKey => {
                write!(f, "metadata did not contain a valid sender APKE key tuple")
            }
            DecryptError::AuthDecFailed => write!(f, "message authentication or decryption failed"),
            DecryptError::MalformedPlaintext => write!(f, "message plaintext was malformed"),
        }
    }
}

/// Error types returned by encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptError {
    /// SD-APKE.AuthEnc failed either authentication or encryption
    AuthEncFailed,
    /// SD-PKE.Enc failed
    MetadataEncFailed,
}

#[cfg_attr(hax, hax_lib::exclude)]
impl core::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptError::AuthEncFailed => write!(f, "message authentication or encryption failed"),
            EncryptError::MetadataEncFailed => write!(f, "metadata seal failed"),
        }
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl core::error::Error for DecryptError {}

#[cfg_attr(hax, hax_lib::exclude)]
impl core::error::Error for EncryptError {}

/// Encrypt a message from a sender to a recipient (step 6).
///
/// Produces an [`Envelope`] containing:
/// - `ct^APKE`: SD-APKE ciphertext (encrypted message)
/// - `ct^PKE`: SD-PKE ciphertext (encrypted sender APKE public key)
/// - `(X, Z)`: hint for privacy-preserving message fetching
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn encrypt<R, Sender, Recipient>(
    rng: &mut R,
    sender: &Sender,
    plaintext: &Plaintext,
    recipient: &Recipient,
) -> Result<Envelope, EncryptError>
where
    R: RngCore + CryptoRng,
    Sender: UserSecret + ?Sized,
    Recipient: UserPublic + ?Sized,
{
    // spec: sk_S^APKE - sender's long-term APKE private key
    let keypair_s = sender.message_auth_keypair();
    // spec: pk_R^APKE - recipient's APKE public key
    let pk_r = recipient.message_enc_pk();
    // spec: pk_R^fetch
    let pk_r_fetch = recipient.fetch_pk();

    // spec: ct^APKE = SD-APKE.AuthEnc(sk_S^APKE, pk_R^APKE, pt, NR, pk_R^fetch)
    let ct_apke = crate::message::auth_enc(
        rng,
        keypair_s,
        pk_r,
        &plaintext.to_bytes(),
        NR_ID,
        pk_r_fetch,
    )
    .map_err(|_| EncryptError::AuthEncFailed)?;

    // Hint (X, Z): X = g^x, Z = (pk_R^fetch)^x for a fresh ephemeral scalar x
    // spec: x (hint_esk), X (hint_epk)
    let (hint_esk, hint_epk) = generate_dh_keypair(rng);
    // spec: Z = (pk_R^fetch)^x
    let hint_sharedsecret: DHPublicKey = dh_shared_secret(recipient.fetch_pk(), &hint_esk);

    // spec: pk_S^APKE - sender's long-term APKE public key
    // spec: ct^PKE = SD-PKE.Enc(pk_R^PKE, pk_S^APKE)
    let ct_pke = metadata::encrypt(rng, recipient.message_metadata_pk(), keypair_s.public_key())
        .map_err(|_| EncryptError::MetadataEncFailed)?;

    Ok(Envelope {
        ct_apke,                 // spec: ct^APKE
        ct_pke,                  // spec: ct^PKE
        mgdh_pubkey: hint_epk,   // spec: X = g^x
        mgdh: hint_sharedsecret, // spec: Z = (pk_R^fetch)^x
    })
}

#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn decrypt<U: UserSecret + ?Sized>(
    receiver: &U,
    envelope: &Envelope,
) -> Result<Plaintext, DecryptError> {
    decrypt_with_sender(receiver, envelope).map(|(p, _)| p)
}

/// Decrypt like [`decrypt`], additionally returning the sender's long-term
/// SD-APKE public key `pk_S^APKE` recovered from `ct^PKE`.
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn decrypt_with_sender<U: UserSecret + ?Sized>(
    receiver: &U,
    envelope: &Envelope,
) -> Result<(Plaintext, MessagePublicKey), DecryptError> {
    // Trial-decrypt ct^PKE with each keybundle's metadata private key to find
    // the intended recipient's bundle. Stop if one succeeds, returning the decrypted metadata and the bundle.
    let (bundle, raw_metadata) = receiver
        .keybundles()
        .iter()
        .find_map(|&bundle| {
            metadata::decrypt(bundle.metadata_kp.private_key(), &envelope.ct_pke)
                .ok()
                .map(|m| (bundle, m))
        })
        .ok_or(DecryptError::NoDecryptingKeyBundle)?;

    // spec: pk_S^APKE - reconstruct sender's APKE public key from decrypted metadata
    let sender_pk =
        MessagePublicKey::from_bytes(&raw_metadata).map_err(|_| DecryptError::InvalidSenderKey)?;

    // spec: pk_R^fetch
    let pk_r_fetch = receiver.fetch_keypair().1;

    // spec: pt = SD-APKE.AuthDec(sk_R^APKE, pk_S^APKE, ct^APKE, NR, pk_R^fetch)
    let pt = crate::message::auth_dec(
        bundle.apke.private_key(), // spec: sk_R^APKE
        &sender_pk,                // spec: pk_S^APKE
        &envelope.ct_apke,         // spec: ct^APKE
        NR_ID,                     // spec: NR
        pk_r_fetch,                // spec: pk_R^fetch
    )
    .map_err(|_| DecryptError::AuthDecFailed)?;

    let plaintext = Plaintext::from_bytes(&pt).map_err(|_| DecryptError::MalformedPlaintext)?;

    Ok((plaintext, sender_pk))
}

/// Build plaintext message, including pubkeys (for replies).
/// Only sources need to attach their pubkeys (for replies),
/// but for toy purposes, everyone builds a Plaintext message the same way
#[cfg(test)]
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub(crate) fn build_message(sender: &impl UserPublic, message: Vec<u8>) -> Plaintext {
    Plaintext {
        sender_fetch_key: *sender.fetch_pk(),
        sender_reply_pubkey_hybrid: sender.message_metadata_pk().clone(),
        msg: message,
    }
}

// Begin unit tests
#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::metadata::MetadataPublicKey;
    use crate::{Journalist, Source, SourcePublicView};

    use super::*;

    // Test purposes only!
    fn setup_rng() -> impl rand_core::CryptoRng + rand_core::RngCore {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed- is platform supported?");
        ChaCha20Rng::from_seed(seed)
    }

    fn assert_encrypt_decrypt<R: CryptoRng + RngCore>(
        rng: &mut R,
        sender_public: &impl UserPublic,
        sender_secret: &impl UserSecret,
        rcvr_public: &impl UserPublic,
        rcvr_secret: &impl UserSecret,
        msg: Vec<u8>,
    ) {
        let pt = build_message(sender_public, msg);

        let envelope = encrypt(rng, sender_secret, &pt, rcvr_public).unwrap();
        let decrypted = decrypt(rcvr_secret, &envelope).unwrap();

        let pt_ref = &pt;

        assert_eq!(pt_ref.msg, decrypted.msg);
        assert_eq!(pt_ref.len(), decrypted.to_bytes().len());

        assert_eq!(
            pt_ref.sender_fetch_key.into_bytes(),
            (*sender_secret.fetch_keypair().1).into_bytes()
        );
        assert_eq!(
            pt_ref.sender_reply_pubkey_hybrid.as_bytes(),
            sender_public.message_metadata_pk().as_bytes()
        );
        assert_eq!(
            pt.len(),
            pt_ref.msg.len() + DHPublicKey::LEN + MetadataPublicKey::LEN
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = setup_rng();

        let sender = Source::new(&mut rng);
        let recipient = Journalist::new(&mut rng, 2);

        let msg = b"Encrypt-decrypt-test".to_vec();

        assert_encrypt_decrypt(
            &mut rng,
            &sender.public(),
            &sender,
            &recipient.public(1),
            &recipient,
            msg,
        );
    }

    #[test]
    fn test_encrypt_decrypt_sourcesource() {
        // we don't want this, but it should work anyway
        let mut rng = setup_rng();
        let sender = Source::new(&mut rng);
        let recipient = Source::new(&mut rng);

        assert_encrypt_decrypt(
            &mut rng,
            &sender.public(),
            &sender,
            &recipient.public(),
            &recipient,
            b"Encrypt-decrypt-test".to_vec(),
        );
    }

    #[test]
    fn test_journalist_reply_to_source_roundtrip() {
        let mut rng = setup_rng();

        // Source submits to journalist.
        let source = Source::new(&mut rng);
        let journalist = Journalist::new(&mut rng, 2);
        let journalist_public = journalist.public(0);

        let submission = build_message(&source.public(), b"howdy".to_vec());
        let envelope = encrypt(&mut rng, &source, &submission, &journalist_public).unwrap();

        // Journalist decrypts and recovers the source's reply keys.
        let (pt, sender_apke) = decrypt_with_sender(&journalist, &envelope).unwrap();
        let reply_recipient = SourcePublicView::from_reply_keys(
            pt.sender_fetch_key,
            sender_apke,
            pt.sender_reply_pubkey_hybrid,
        );

        // Journalist encrypts a reply back to the source.
        let reply_text = b"thanks dawg".to_vec();
        let reply_pt = journalist.build_message(reply_text.clone());
        let reply_envelope = encrypt(&mut rng, &journalist, &reply_pt, &reply_recipient).unwrap();

        // Source decrypts the reply.
        let decrypted = decrypt(&source, &reply_envelope).unwrap();
        assert_eq!(decrypted.msg, reply_text);
    }

    #[test]
    fn test_encrypt_decrypt_journalist_only() {
        let mut rng = setup_rng();

        let journalist = Journalist::new(&mut rng, 2);
        let j2 = Journalist::new(&mut rng, 2);

        let msg = "Test message".as_bytes().to_vec();

        assert_encrypt_decrypt(
            &mut rng,
            &journalist.public(0),
            &journalist,
            &j2.public(0),
            &j2,
            msg,
        );
    }

    #[test]
    fn test_no_decrypting_key_bundle() {
        let mut rng = setup_rng();

        // Source submits to journalist A.
        let source = Source::new(&mut rng);
        let journalist = Journalist::new(&mut rng, 2);
        let journalist_public = journalist.public(0);

        let submission = build_message(&source.public(), b"howdy".to_vec());
        let envelope = encrypt(&mut rng, &source, &submission, &journalist_public).unwrap();

        // Journalist 2 decrypts
        let j2 = Journalist::new(&mut rng, 2);
        assert_eq!(
            decrypt_with_sender(&j2, &envelope).unwrap_err(),
            DecryptError::NoDecryptingKeyBundle
        );
    }

    #[test]
    fn test_auth_dec_failed() {
        let mut rng = setup_rng();

        // Source submits to journalist A.
        let source = Source::new(&mut rng);
        let journalist = Journalist::new(&mut rng, 2);
        let journalist_public = journalist.public(0);

        let submission = build_message(&source.public(), b"howdy".to_vec());
        let mut envelope = encrypt(&mut rng, &source, &submission, &journalist_public).unwrap();

        envelope.ct_apke.c1[0] ^= 0x01; // Corrupt the ciphertext
        assert_eq!(
            decrypt_with_sender(&journalist, &envelope).unwrap_err(),
            DecryptError::AuthDecFailed
        );
    }

    #[test]
    fn test_encrypt_error() {
        let mut rng = setup_rng();

        // Source submits to journalist.
        let source = Source::new(&mut rng);
        let journalist = Journalist::new(&mut rng, 2);
        let journalist_public = journalist.public(0);

        // Malicious source builds a message plaintext with a zero-d x25519 part of the MetadataPublicKey
        let mut bytes = source.public().message_metadata_pk().as_bytes().to_vec();
        let x25519_start = bytes.len() - 32; // x25519 point of the pk
        bytes[x25519_start..].fill(0);
        let zero_pk = MetadataPublicKey::from_bytes(&bytes).expect("correct length");

        let submission = Plaintext {
            sender_fetch_key: *source.public().fetch_pk(),
            sender_reply_pubkey_hybrid: zero_pk,
            msg: b"zero key msg".to_vec(),
        };
        let envelope = encrypt(&mut rng, &source, &submission, &journalist_public).unwrap();

        // Journalist decrypts and recovers the source's reply keys.
        let (pt, sender_apke) = decrypt_with_sender(&journalist, &envelope).unwrap();
        let reply_recipient = SourcePublicView::from_reply_keys(
            pt.sender_fetch_key,
            sender_apke,
            pt.sender_reply_pubkey_hybrid,
        );

        // Journalist encrypts a reply back to the source.
        let reply_text = b"thanks dawg".to_vec();
        let reply_pt = journalist.build_message(reply_text.clone());
        assert_eq!(
            encrypt(&mut rng, &journalist, &reply_pt, &reply_recipient).unwrap_err(),
            EncryptError::MetadataEncFailed
        );
    }
}
