use std::collections::HashSet;

use anyhow::{Context, Result};
use securedrop_protocol_minimal::api::{Api, Client};
use securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender;
use securedrop_protocol_minimal::wire::core::{
    MessageChallengeFetchResponse, SourceJournalistKeyResponse, SourceNewsroomKeyResponse,
};
use securedrop_protocol_minimal::{Envelope, Source, UserPublic};

use crate::util::{parse_fpf_vk, read_passphrase};

pub(crate) fn fetch(server: &str, fpf_vk_hex: &str) -> Result<()> {
    let fpf_vk = parse_fpf_vk(fpf_vk_hex)?;

    let passphrase = read_passphrase()?;
    let mut source = Source::from_passphrase(passphrase.trim())
        .context("not a valid BIP39 recovery passphrase")?;
    let client = reqwest::blocking::Client::new();

    // Establish the trust chain so we can authenticate reply senders: verify the
    // newsroom key against the pinned FPF key, then fetch and verify the enrolled
    // journalists' keys. A reply is only trusted if its sender's long-term APKE
    // key belongs to one of these journalists.
    let nr_resp: SourceNewsroomKeyResponse = client
        .get(format!("{server}/newsroom/keys"))
        .send()
        .with_context(|| format!("fetching {server}/newsroom/keys"))?
        .error_for_status()
        .context("newsroom rejected key request")?
        .json()?;
    source
        .handle_newsroom_key_response(&nr_resp, &fpf_vk)
        .context("newsroom key response failed verification against the pinned FPF key")?;
    let newsroom_vk = *source
        .newsroom_verifying_key()
        .expect("newsroom key stored by handle_newsroom_key_response");

    // Fetch and verify the journalists' keys via the same endpoint
    //
    // TODO: Should this be split into 2 endpoints? One for long-term keys and one for ephemeral keys?
    // otherwise we're consuming bundles for no reason afaict
    let journalists: Vec<SourceJournalistKeyResponse> = client
        .get(format!("{server}/journalists/keys"))
        .send()
        .with_context(|| format!("fetching {server}/journalists/keys"))?
        .error_for_status()
        .context("newsroom rejected journalist key request")?
        .json()?;
    let mut trusted_senders: HashSet<Vec<u8>> = HashSet::new();
    for resp in &journalists {
        source
            .handle_journalist_key_response(resp, &newsroom_vk)
            .context("journalist key response failed verification")?;
        // A journalist replies using their long-term APKE key.
        trusted_senders.insert(resp.journalist.message_auth_pk().as_bytes());
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
        if !trusted_senders.contains(&sender_apke.as_bytes()) {
            // Reply from a sender that isn't an enrolled journalist, discard
            // TODO: delete?
            discarded += 1;
            continue;
        }

        let msg = strip_padding(&plaintext.msg);
        println!("[{id}]");
        println!("{}\n", String::from_utf8_lossy(msg));
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

/// Strip the trailing zero padding applied at submission time
fn strip_padding(msg: &[u8]) -> &[u8] {
    let end = msg.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &msg[..end]
}
