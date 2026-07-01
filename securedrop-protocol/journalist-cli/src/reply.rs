use anyhow::{Context, Result};
use rand_core::{CryptoRng, RngCore};
use securedrop_protocol_minimal::api::Api;
use securedrop_protocol_minimal::wire::core::{JournalistEphemeralKeys, WelcomeBundle};
use securedrop_protocol_minimal::{
    Enrollable, Journalist, JournalistPublicView, SourcePublicView, UserPublic,
};
use serde::Deserialize;

use crate::storage::{load_inbox, load_journalist, load_newsroom_vk};

#[derive(Deserialize)]
struct MessageSubmitResponse {
    message_id: String,
}

pub(crate) fn reply(server: &str, message_id: &str, message: &str) -> Result<()> {
    let journalist = load_journalist()?;
    let own_vk = journalist.signing_key().into_bytes();

    let inbox = load_inbox()?;
    let entry = inbox
        .iter()
        .find(|e| e.message_id == message_id)
        .with_context(|| format!("message {message_id} not found in inbox: run `fetch`"))?;

    let source = SourcePublicView::from_reply_keys(
        entry.sender_fetch_pk.clone(),
        entry.sender_apke_pk.clone(),
        entry.sender_metadata_pk.clone(),
    );

    let newsroom_vk = load_newsroom_vk()?;
    let client = reqwest::blocking::Client::new();

    // Welcome bundle - we need this for our fellow journos
    let welcome: WelcomeBundle = client
        .get(format!("{server}/welcome"))
        .send()
        .with_context(|| format!("fetching {server}/welcome"))?
        .error_for_status()
        .context("newsroom rejected welcome request")?
        .json()?;
    let ephemeral: Vec<JournalistEphemeralKeys> = client
        .get(format!("{server}/journalists/keys"))
        .send()
        .with_context(|| format!("fetching {server}/journalists/keys"))?
        .error_for_status()
        .context("newsroom rejected ephemeral key request")?
        .json()?;

    let mut other_journalists: Vec<JournalistPublicView> = Vec::new();
    for eph in &ephemeral {
        // we don't want to reply to ourselves
        if eph.vk.into_bytes() == own_vk {
            continue;
        }
        let Some(long_term) = welcome
            .journalists
            .iter()
            .find(|j| j.vk.into_bytes() == eph.vk.into_bytes())
        else {
            continue;
        };
        journalist
            .verify_long_term(long_term, &newsroom_vk)
            .context("journalist long-term keys failed verification")?;
        let view = journalist
            .verify_ephemeral(long_term, &eph.ephemeral)
            .context("journalist one-time keys failed verification")?;
        other_journalists.push(view);
    }

    // Send the reply to the source and to every other journalist so they have the convo history
    let mut rng = rand::rng();
    let mut message_ids = Vec::new();
    message_ids.push(send_reply(
        &client,
        server,
        &journalist,
        &source,
        message,
        &mut rng,
    )?);
    for view in &other_journalists {
        message_ids.push(send_reply(
            &client,
            server,
            &journalist,
            view,
            message,
            &mut rng,
        )?);
    }

    println!(
        "Reply submitted to {} recipient(s) (source + {} other journalist(s)) at {server}.\n",
        message_ids.len(),
        message_ids.len() - 1
    );
    for id in &message_ids {
        println!("Message ID: {id}");
    }
    Ok(())
}

/// Encrypt `message` from the journalist to one recipient and submit the envelope,
/// returning the message ID.
fn send_reply<R: RngCore + CryptoRng, P: UserPublic>(
    client: &reqwest::blocking::Client,
    server: &str,
    journalist: &Journalist,
    recipient: &P,
    message: &str,
    rng: &mut R,
) -> Result<String> {
    let envelope = journalist
        .submit_message(rng, message.as_bytes(), journalist, recipient)
        .context("encrypting reply")?;

    let submitted: MessageSubmitResponse = client
        .post(format!("{server}/messages"))
        .json(&envelope)
        .send()
        .context("submitting reply")?
        .error_for_status()
        .context("newsroom rejected reply")?
        .json()?;
    Ok(submitted.message_id)
}
