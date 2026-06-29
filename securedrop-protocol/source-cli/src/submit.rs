use anyhow::{Context, Result, bail};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::Source;
use securedrop_protocol_minimal::api::{Api, Client};
use securedrop_protocol_minimal::wire::core::{
    SourceJournalistKeyResponse, SourceNewsroomKeyResponse,
};
use serde::Deserialize;

use crate::util::{parse_fpf_vk, read_passphrase};

#[derive(Deserialize)]
struct MessageSubmitResponse {
    message_id: String,
}

pub(crate) fn submit(server: &str, fpf_vk_hex: &str, message: &str) -> Result<()> {
    let fpf_vk = parse_fpf_vk(fpf_vk_hex)?;

    let passphrase = read_passphrase()?;
    let mut source = Source::from_passphrase(passphrase.trim())
        .context("not a valid BIP39 recovery passphrase")?;
    let mut rng = OsRng.unwrap_err();
    let client = reqwest::blocking::Client::new();

    // Fetch the newsroom key and verify FPF's signature over it.
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

    // Fetch one long term key and one ephemeral key bundle per journo.
    let journalists: Vec<SourceJournalistKeyResponse> = client
        .get(format!("{server}/journalists/keys"))
        .send()
        .with_context(|| format!("fetching {server}/journalists/keys"))?
        .error_for_status()
        .context("newsroom rejected journalist key request")?
        .json()?;
    if journalists.is_empty() {
        bail!("no journalists available (none enrolled, or all out of ephemeral keys)");
    }

    // Encrypt the message to each journalist and submit one envelope each.
    let mut message_ids = Vec::new();
    for resp in &journalists {
        source
            .handle_journalist_key_response(resp, &newsroom_vk)
            .context("journalist key response failed verification")?;

        let envelope = source
            .submit_message(&mut rng, message.as_bytes(), &source, &resp.journalist)
            .context("encrypting message")?;

        let submitted: MessageSubmitResponse = client
            .post(format!("{server}/messages"))
            .json(&envelope)
            .send()
            .context("submitting message")?
            .error_for_status()
            .context("newsroom rejected message")?
            .json()?;
        message_ids.push(submitted.message_id);
    }

    println!(
        "Submitted to {} journalist(s) at {server}.\n",
        message_ids.len()
    );
    for id in &message_ids {
        println!("Message ID: {id}");
    }
    Ok(())
}
