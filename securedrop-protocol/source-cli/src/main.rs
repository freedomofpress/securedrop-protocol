//! Demo source CLI for the SecureDrop protocol.

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::api::{Api, Client};
use securedrop_protocol_minimal::wire::core::{
    SourceJournalistKeyResponse, SourceNewsroomKeyResponse,
};
use securedrop_protocol_minimal::{Source, UserPublic, VerifyingKey};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "source-cli", about = "Demo SecureDrop source client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Note: The FPF verifying key _would_ be pinned in the client, but here
/// we pass it.
#[derive(Subcommand)]
enum Command {
    /// Generate a new source identity and print its recovery passphrase.
    Generate,
    /// Rederive a source identity from its passphrase and print its public keys.
    Show,
    /// Submit a message to every enrolled journalist of a newsroom.
    Submit {
        /// Newsroom server URL.
        #[arg(long)]
        server: String,
        /// FPF verifying key as 64 hex characters.
        #[arg(long = "fpf-vk")]
        fpf_vk: String,
        /// The message to send.
        #[arg(short, long)]
        message: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate => generate(),
        Command::Show => show(),
        Command::Submit {
            server,
            fpf_vk,
            message,
        } => submit(&server, &fpf_vk, &message),
    }
}

fn generate() -> Result<()> {
    let source = Source::new(OsRng.unwrap_err());
    let mnemonic = source.passphrase();
    let fetch_pk = source.public().fetch_pk().into_bytes();

    println!("New source identity");
    println!();
    println!("Recovery passphrase (write this down!!):");
    println!("  {mnemonic}");
    println!();
    println!("Fetch public key: {}", hex(&fetch_pk));
    Ok(())
}

fn show() -> Result<()> {
    let passphrase = read_passphrase()?;
    let source = Source::from_passphrase(passphrase.trim())
        .context("not a valid BIP39 recovery passphrase")?;
    let fetch_pk = source.public().fetch_pk().into_bytes();

    println!("Fetch public key: {}", hex(&fetch_pk));
    Ok(())
}

#[derive(Deserialize)]
struct MessageSubmitResponse {
    message_id: String,
}

fn submit(server: &str, fpf_vk_hex: &str, message: &str) -> Result<()> {
    let mut fpf_vk_bytes = [0u8; 32];
    hex::decode_to_slice(fpf_vk_hex.trim(), &mut fpf_vk_bytes)
        .context("parsing FPF verifying key")?;
    let fpf_vk = VerifyingKey::from_bytes(fpf_vk_bytes);

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

/// Obtain the source passphrase without persisting it: prefer the
/// `SOURCE_PASSPHRASE` environment variable, otherwise prompt on stdin.
fn read_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("SOURCE_PASSPHRASE") {
        if !p.trim().is_empty() {
            return Ok(p);
        }
    }
    if io::stdin().is_terminal() {
        eprint!("Enter source passphrase: ");
        io::stderr().flush().ok();
    }
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("reading passphrase from stdin")?;
    Ok(line)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
