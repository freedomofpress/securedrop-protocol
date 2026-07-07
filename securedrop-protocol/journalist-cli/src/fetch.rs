use anyhow::{Context, Result};
use securedrop_protocol_minimal::Envelope;
use securedrop_protocol_minimal::api::Api;
use securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender;
use securedrop_protocol_minimal::metadata::MetadataPublicKey;
use securedrop_protocol_minimal::primitives::x25519::DHPublicKey;
use securedrop_protocol_minimal::wire::core::MessageChallengeFetchResponse;

use crate::storage::{InboxEntry, load_ephemeral_secrets, load_inbox, load_journalist, save_inbox};

pub(crate) fn fetch(server: &str) -> Result<()> {
    // Load the long term keys plus the retained ephemeral secrets
    // The fetch key solves the challenges, and the ephemeral bundles decrypt the messages.
    let mut journalist = load_journalist()?;
    journalist.load_ephemeral_bundles(load_ephemeral_secrets()?);

    let client = reqwest::blocking::Client::new();

    // Fetch the challenge set and solve it with our fetch key.
    let challenges: MessageChallengeFetchResponse = client
        .get(format!("{server}/challenges"))
        .send()
        .with_context(|| format!("fetching {server}/challenges"))?
        .error_for_status()
        .context("newsroom rejected challenge request")?
        .json()?;
    let message_ids = journalist
        .solve_fetch_challenges(&challenges.messages)
        .context("solving fetch challenges")?;

    // Download and decrypt anything new, persist it locally, then delete it from
    // the server.
    let mut inbox = load_inbox()?;
    let mut new_count = 0;
    for id in message_ids {
        let id_str = id.to_string();
        if inbox.iter().any(|e| e.message_id == id_str) {
            continue;
        }

        let envelope: Envelope = client
            .get(format!("{server}/messages/{id}"))
            .send()
            .with_context(|| format!("fetching message {id}"))?
            .error_for_status()
            .context("newsroom rejected message download")?
            .json()?;

        let (plaintext, sender_apke) = decrypt_with_sender(&journalist, &envelope);
        let text = String::from_utf8_lossy(&plaintext.msg).into_owned();
        let sender_metadata_pk =
            MetadataPublicKey::from_bytes(&plaintext.sender_reply_pubkey_hybrid)
                .context("recovered source metadata key is malformed")?;

        inbox.push(InboxEntry {
            message_id: id_str,
            text,
            sender_fetch_pk: DHPublicKey::from_bytes(plaintext.sender_fetch_key),
            sender_apke_pk: sender_apke,
            sender_metadata_pk,
        });
        new_count += 1;

        // Confirm receipt by deleting the server's copy.
        client
            .delete(format!("{server}/messages/{id}"))
            .send()
            .with_context(|| format!("deleting message {id}"))?
            .error_for_status()
            .context("newsroom rejected message deletion")?;
    }
    save_inbox(&inbox)?;

    if inbox.is_empty() {
        println!("No messages.");
        return Ok(());
    }

    println!("{} new message(s); {} in inbox.\n", new_count, inbox.len());
    for entry in &inbox {
        println!("[{}]", entry.message_id);
        println!("{}\n", entry.text);
    }
    Ok(())
}
