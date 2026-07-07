use std::collections::HashSet;

use anyhow::{Context, Result};
use securedrop_protocol_minimal::api::Api;
use securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender;
use securedrop_protocol_minimal::wire::core::{MessageChallengeFetchResponse, WelcomeBundle};
use securedrop_protocol_minimal::{Envelope, Source, UserPublic};

use crate::util::{parse_fpf_vk, read_passphrase};

pub(crate) fn fetch(server: &str, fpf_vk_hex: &str) -> Result<()> {
    let fpf_vk = parse_fpf_vk(fpf_vk_hex)?;

    let passphrase = read_passphrase()?;
    let mut source = Source::from_passphrase(passphrase.trim())
        .context("not a valid BIP39 recovery passphrase")?;
    let client = reqwest::blocking::Client::new();

    let welcome: WelcomeBundle = client
        .get(format!("{server}/welcome"))
        .send()
        .with_context(|| format!("fetching {server}/welcome"))?
        .error_for_status()
        .context("newsroom rejected welcome request")?
        .json()?;
    source
        .handle_welcome(&welcome, &fpf_vk)
        .context("welcome bundle failed verification against the pinned FPF key")?;

    let mut trusted_senders: HashSet<Vec<u8>> = HashSet::new();
    for journalist in &welcome.journalists {
        // A journalist replies using their long-term APKE key.
        trusted_senders.insert(journalist.reply_apke_pk.as_bytes().to_vec());
    }

    // Fetch the challenge set and solve it with our fetch key.
    let challenges: MessageChallengeFetchResponse = client
        .get(format!("{server}/challenges"))
        .send()
        .with_context(|| format!("fetching {server}/challenges"))?
        .error_for_status()
        .context("newsroom rejected challenge request")?
        .json()?;
    let message_ids = source
        .solve_fetch_challenges(&challenges.messages)
        .context("solving fetch challenges")?;

    if message_ids.is_empty() {
        println!("No messages.");
        return Ok(());
    }

    // Download and decrypt each message addressed to us. Display and delete only
    // those from a recognized journalist, drop the rest.
    let mut shown = 0;
    let mut discarded = 0;
    for id in message_ids {
        let envelope: Envelope = client
            .get(format!("{server}/messages/{id}"))
            .send()
            .with_context(|| format!("fetching message {id}"))?
            .error_for_status()
            .context("newsroom rejected message download")?
            .json()?;

        let (plaintext, sender_apke) = decrypt_with_sender(&source, &envelope);
        if !trusted_senders.contains(&sender_apke.as_bytes().to_vec()) {
            // Reply from a sender that isn't an enrolled journalist, discard
            // TODO: delete?
            discarded += 1;
            continue;
        }

        println!("[{id}]");
        println!("{}\n", String::from_utf8_lossy(&plaintext.msg));
        shown += 1;

        // Confirm receipt by deleting the server's copy.
        client
            .delete(format!("{server}/messages/{id}"))
            .send()
            .with_context(|| format!("deleting message {id}"))?
            .error_for_status()
            .context("newsroom rejected message deletion")?;
    }

    if shown == 0 {
        println!("No messages.");
    }
    if discarded > 0 {
        println!("Discarded {discarded} message(s) from unrecognized senders.");
    }
    Ok(())
}
