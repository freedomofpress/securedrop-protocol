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
) -> Envelope
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
    .expect("SD-APKE AuthEnc failed");

    // Hint (X, Z): X = g^x, Z = (pk_R^fetch)^x for a fresh ephemeral scalar x
    // spec: x (hint_esk), X (hint_epk)
    let (hint_esk, hint_epk) = generate_dh_keypair(rng);
    // spec: Z = (pk_R^fetch)^x
    let hint_sharedsecret: DHPublicKey = dh_shared_secret(recipient.fetch_pk(), &hint_esk);

    // spec: pk_S^APKE - sender's long-term APKE public key
    // spec: ct^PKE = SD-PKE.Enc(pk_R^PKE, pk_S^APKE)
    // TODO: Refactor to return Result<T, E> instead of panicking at failed metadata seal
    let ct_pke = metadata::encrypt(
        rng,
        recipient.message_metadata_pk(),
        &keypair_s.public_key(),
    )
    .expect("Valid Keybundle should allow metadata seal");

    Envelope {
        ct_apke,                 // spec: ct^APKE
        ct_pke,                  // spec: ct^PKE
        mgdh_pubkey: hint_epk,   // spec: X = g^x
        mgdh: hint_sharedsecret, // spec: Z = (pk_R^fetch)^x
    }
}

#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn decrypt<U: UserSecret + ?Sized>(receiver: &U, envelope: &Envelope) -> Plaintext {
    decrypt_with_sender(receiver, envelope).0
}

/// Decrypt like [`decrypt`], additionally returning the sender's long-term
/// SD-APKE public key `pk_S^APKE` recovered from `ct^PKE`.
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn decrypt_with_sender<U: UserSecret + ?Sized>(
    receiver: &U,
    envelope: &Envelope,
) -> (Plaintext, MessagePublicKey) {
    // Trial-decrypt ct^PKE with each keybundle's metadata private key to find
    // the intended recipient's bundle. There should be exactly 1 result.
    let mut found: Option<(&MessageKeyBundle, Vec<u8>)> = None;
    for &bundle in receiver.keybundles().iter() {
        if let Ok(m) = metadata::decrypt(bundle.metadata_kp.private_key(), &envelope.ct_pke) {
            found = Some((bundle, m));
        }
    }

    // TODO: only true for test purposes!
    let (bundle, raw_metadata) = found.expect("we should find exactly 1 result");

    // spec: pk_S^APKE - reconstruct sender's APKE public key from decrypted metadata
    let sender_pk = MessagePublicKey::from_bytes(&raw_metadata)
        .expect("Metadata must contain valid sender APKE key tuple");

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
    .expect("SD-APKE AuthDec failed");

    (Plaintext::from_bytes(&pt).unwrap(), sender_pk)
}

/// Build plaintext message, including pubkeys (for replies).
/// TODO: only sources need to attach their pubkeys (for replies),
/// but for toy purposes, everyone builds a Plaintext message the same way
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn build_message(sender: &impl UserPublic, message: Vec<u8>) -> Plaintext {
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

        let envelope = encrypt(rng, sender_secret, &pt, rcvr_public);
        let decrypted = decrypt(rcvr_secret, &envelope);

        let pt_ref = &pt;

        assert_eq!(pt_ref.msg, decrypted.msg);
        assert_eq!(pt_ref.len(), decrypted.to_bytes().len());

        assert_eq!(
            pt_ref.sender_fetch_key.into_bytes(),
            sender_secret.fetch_keypair().1.clone().into_bytes()
        );
        assert_eq!(
            pt_ref.sender_reply_pubkey_hybrid.as_bytes(),
            sender_public.message_metadata_pk().as_bytes()
        );
        assert_eq!(
            pt.len(),
            &pt_ref.msg.len() + DHPublicKey::LEN + MetadataPublicKey::LEN
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
        let envelope = encrypt(&mut rng, &source, &submission, &journalist_public);

        // Journalist decrypts and recovers the source's reply keys.
        let (pt, sender_apke) = decrypt_with_sender(&journalist, &envelope);
        let reply_recipient = SourcePublicView::from_reply_keys(
            pt.sender_fetch_key,
            sender_apke,
            pt.sender_reply_pubkey_hybrid,
        );

        // Journalist encrypts a reply back to the source.
        let reply_text = b"thanks dawg".to_vec();
        let reply_pt = journalist.build_message(reply_text.clone());
        let reply_envelope = encrypt(&mut rng, &journalist, &reply_pt, &reply_recipient);

        // Source decrypts the reply.
        let decrypted = decrypt(&source, &reply_envelope);
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
}
