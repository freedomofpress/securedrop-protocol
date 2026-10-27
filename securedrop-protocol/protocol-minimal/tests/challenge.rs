use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use securedrop_protocol_minimal::{
    Envelope, Journalist, Source,
    client::{
        challenge::solve_fetch_challenges,
        message::{build_message, encrypt},
    },
    server::challenge::compute_fetch_challenges,
};
use uuid::Uuid;

// Test purposes only!
fn setup_rng() -> impl rand_core::CryptoRng + rand_core::RngCore {
    let mut seed = [0u8; 32];
    #[allow(clippy::disallowed_methods)]
    getrandom::fill(&mut seed).expect("getrandom failed- is platform supported?");
    ChaCha20Rng::from_seed(seed)
}

// Build a random message ID. Avoids using ServerStorage in tests
fn random_message_id<R: rand_core::RngCore>(rng: &mut R) -> Uuid {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

#[test]
fn test_fetch_challenges_roundtrip() {
    let mut rng = setup_rng();

    let source = Source::new(&mut rng);
    let journalist = Journalist::new(&mut rng, 2);

    // pubkey-only capabilities (for receiver)
    let journalist_public = journalist.public(0);

    let msg = b"Fetch this message";
    let plaintext = build_message(&source.public(), msg.to_vec());
    let envelope = encrypt(&mut rng, &source, &plaintext, &journalist_public);

    let mut entries: Vec<([u8; 16], Envelope)> = Vec::new();
    let message_id = random_message_id(&mut rng);

    entries.push((*message_id.as_bytes(), envelope));

    let challenges = compute_fetch_challenges(&mut rng, &entries, 2);

    let solved_ids = solve_fetch_challenges(&journalist, &challenges);

    assert_eq!(solved_ids.len(), 1);
    assert_eq!(solved_ids[0], message_id);
}

#[test]
fn test_wrong_recipient_cannot_decrypt_challenge() {
    let mut rng = setup_rng();

    let source = Source::new(&mut rng);
    let journalist = Journalist::new(&mut rng, 2);

    let wrong_journalist = Journalist::new(&mut rng, 2);

    // pubkey-only capabilities (for receiver)
    let journalist_public = journalist.public(0);

    let msg = b"Fetch this message";
    let plaintext = build_message(&source.public(), msg.to_vec());
    let envelope = encrypt(&mut rng, &source, &plaintext, &journalist_public);

    let mut entries: Vec<([u8; 16], Envelope)> = Vec::new();
    let message_id = random_message_id(&mut rng);

    entries.push((*message_id.as_bytes(), envelope));

    let challenges = compute_fetch_challenges(&mut rng, &entries, 2);

    let solved_ids = solve_fetch_challenges(&journalist, &challenges);

    let solved_ids_miss = solve_fetch_challenges(&wrong_journalist, &challenges);

    assert_eq!(solved_ids.len(), 1);
    assert_eq!(solved_ids[0], message_id);
    assert_eq!(solved_ids_miss.len(), 0);
}
