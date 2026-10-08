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
        trusted_senders.insert(journalist.signed_longterm_key_bundle.apke().as_bytes());
    }

    let mut fetched: HashSet<String> = HashSet::new();
    let mut shown = 0;
    let mut discarded = 0;

    // in the spec in step 7, we request a fresh challenge set, solve it,
    // download at most one new message, then repeat from `RequestMessages` while
    // anything remains
    loop {
        let challenges: MessageChallengeFetchResponse = client
            .get(format!("{server}/challenges"))
            .send()
            .with_context(|| format!("fetching {server}/challenges"))?
            .error_for_status()
            .context("newsroom rejected challenge request")?
            .json()?;
        let cids = source
            .solve_fetch_challenges(&challenges.messages)
            .context("solving fetch challenges")?;

        let Some(id) = cids
            .into_iter()
            .find(|cid| !fetched.contains(&cid.to_string()))
        else {
            break;
        };

        let envelope: Envelope = client
            .get(format!("{server}/messages/{id}"))
            .send()
            .with_context(|| format!("fetching message {id}"))?
            .error_for_status()
            .context("newsroom rejected message download")?
            .json()?;

        let (plaintext, sender_apke) = decrypt_with_sender(&source, &envelope);
        fetched.insert(id.to_string());
        if !trusted_senders.contains(&sender_apke.as_bytes()) {
            // Reply from a sender that isn't an enrolled journalist, discard
            discarded += 1;
            continue;
        }

        let msg = strip_padding(&plaintext.msg);
        println!("[{id}]");
        println!("{}\n", String::from_utf8_lossy(msg));
        shown += 1;
    }

    if shown == 0 {
        println!("No messages.");
    }
    if discarded > 0 {
        println!("Discarded {discarded} message(s) from unrecognized senders.");
    }
    Ok(())
}

/// Strip the trailing zero padding applied at submission time
fn strip_padding(msg: &[u8]) -> &[u8] {
    let end = msg.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &msg[..end]
}
