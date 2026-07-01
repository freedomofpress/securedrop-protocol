use anyhow::{Context, Result, bail};
use securedrop_protocol_minimal::Source;
use securedrop_protocol_minimal::api::Api;
use securedrop_protocol_minimal::wire::core::{JournalistEphemeralKeys, WelcomeBundle};
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
    let mut rng = rand::rng();
    let client = reqwest::blocking::Client::new();

    // Fetch the newsroom welcome bundle again (we can cache this in the future)
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
    if welcome.journalists.is_empty() {
        bail!("no journalists enrolled at this newsroom");
    }

    // Fetch one one-time key bundle per journalist (this consumes them).
    let ephemeral: Vec<JournalistEphemeralKeys> = client
        .get(format!("{server}/journalists/keys"))
        .send()
        .with_context(|| format!("fetching {server}/journalists/keys"))?
        .error_for_status()
        .context("newsroom rejected ephemeral key request")?
        .json()?;
    if ephemeral.is_empty() {
        bail!("no journalist ephemeral keys available (all out of one-time keys)");
    }

    // Pair each one-time bundle with its journalist's (verified) long-term keys,
    // assemble the public view, encrypt, and submit one envelope each.
    let mut message_ids = Vec::new();
    for eph in &ephemeral {
        let Some(long_term) = welcome
            .journalists
            .iter()
            .find(|j| j.vk.into_bytes() == eph.vk.into_bytes())
        else {
            // one-time keys for a journalist not in the welcome roster... skipping
            continue;
        };
        let journalist = source
            .verify_ephemeral(long_term, &eph.ephemeral)
            .context("journalist one-time key failed verification")?;

        let envelope = source
            .submit_message(&mut rng, message.as_bytes(), &source, &journalist)
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
