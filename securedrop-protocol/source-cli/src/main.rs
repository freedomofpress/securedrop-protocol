//! Demo source CLI for the SecureDrop protocol.

use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::api::{Api, Client};
use securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender;
use securedrop_protocol_minimal::wire::core::{
    MessageChallengeFetchResponse, SourceJournalistKeyResponse, SourceNewsroomKeyResponse,
};
use securedrop_protocol_minimal::{Envelope, Source, UserPublic, VerifyingKey};
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
    /// Fetch and decrypt replies addressed to this source.
    Fetch {
        /// Newsroom server URL.
        #[arg(long)]
        server: String,
        /// FPF verifying key as 64 hex characters.
        #[arg(long = "fpf-vk")]
        fpf_vk: String,
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
        Command::Fetch { server, fpf_vk } => fetch(&server, &fpf_vk),
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

fn fetch(server: &str, fpf_vk_hex: &str) -> Result<()> {
    let mut fpf_vk_bytes = [0u8; 32];
    hex::decode_to_slice(fpf_vk_hex.trim(), &mut fpf_vk_bytes)
        .context("parsing FPF verifying key")?;
    let fpf_vk = VerifyingKey::from_bytes(fpf_vk_bytes);

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

    // Fetch and verify the journalists' keys via the same endpoint.
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
