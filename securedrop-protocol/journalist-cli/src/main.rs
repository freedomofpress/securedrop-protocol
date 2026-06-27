//! Demo SecureDrop journalist client.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand_core::{CryptoRng, OsRng, RngCore, TryRngCore};
use securedrop_protocol_minimal::api::{Api, JournalistApi};
use securedrop_protocol_minimal::encrypt_decrypt::decrypt_with_sender;
use securedrop_protocol_minimal::message::MessagePublicKey;
use securedrop_protocol_minimal::metadata::MetadataPublicKey;
use securedrop_protocol_minimal::primitives::x25519::DHPublicKey;
use securedrop_protocol_minimal::wire::core::{
    MessageChallengeFetchResponse, SourceJournalistKeyResponse,
};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyResponse, JournalistSetupRequest, JournalistSetupResponse,
};
use securedrop_protocol_minimal::{
    Enrollable, Envelope, EphemeralBundleBytes, Journalist, JournalistLongTermBytes,
    JournalistPublic, SourcePublicView, UserPublic, VerifyingKey,
};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "journalist-cli", about = "Demo SecureDrop journalist client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the journalist's long-term keys and persist them.
    Init {
        /// Overwrite an existing journalist key file.
        #[arg(long)]
        force: bool,
    },
    /// Enroll with a newsroom server.
    Enroll {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
        /// Overwrite an existing stored enrollment.
        #[arg(long)]
        force: bool,
    },
    /// Generate fresh ephemeral key bundles and upload them to the server.
    Replenish {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
        /// Number of ephemeral key bundles to generate and upload.
        #[arg(long, default_value_t = 10)]
        count: usize,
    },
    /// Fetch and decrypt messages addressed to this journalist.
    Fetch {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
    },
    /// Reply to a source message (identified by its message ID from `fetch`).
    Reply {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
        /// The message ID to reply to, as printed by `fetch`.
        #[arg(long = "message-id")]
        message_id: String,
        /// The reply text to send.
        #[arg(short, long)]
        message: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { force } => init(force),
        Command::Enroll { server, force } => enroll(&server, force),
        Command::Replenish { server, count } => replenish(&server, count),
        Command::Fetch { server } => fetch(&server),
        Command::Reply {
            server,
            message_id,
            message,
        } => reply(&server, &message_id, &message),
    }
}

#[derive(Deserialize)]
struct NewsroomInfo {
    verifying_key: String,
}

#[derive(Deserialize)]
struct MessageSubmitResponse {
    message_id: String,
}

/// A received message retained locally after `fetch` deletes it from the server.
///
/// Stores the decrypted text and the source's recovered reply keys
/// (so reply can encrypt back to them without DLing from the server,
/// because the server no longer has the message).
#[derive(Serialize, Deserialize)]
struct InboxEntry {
    message_id: String,
    text: String,
    sender_fetch_pk: DHPublicKey,
    sender_apke_pk: MessagePublicKey,
    sender_metadata_pk: MetadataPublicKey,
}

fn init(force: bool) -> Result<()> {
    let path = long_term_path()?;
    if path.exists() && !force {
        bail!(
            "a journalist key already exists at {}\nuse `init --force` to overwrite it",
            path.display()
        );
    }

    let mut rng = OsRng.unwrap_err();
    let journalist = Journalist::new(&mut rng, 0);
    let vk = (*journalist.signing_key()).into_bytes();
    let bytes = journalist.long_term_bytes().as_bytes();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &bytes)?;

    println!("Saved to:                 {}", path.display());
    println!("Journalist verifying key: {}\n", hex::encode(vk));
    println!("Hand this verifying key to the newsroom for signing.");
    Ok(())
}

fn enroll(server: &str, force: bool) -> Result<()> {
    let sig_path = newsroom_sig_path()?;
    let vk_path = newsroom_vk_path()?;
    if (sig_path.exists() || vk_path.exists()) && !force {
        bail!(
            "newsroom enrollment already exists at {} and {}\nuse `enroll --force` to overwrite it",
            sig_path.display(),
            vk_path.display()
        );
    }

    let journalist = load_journalist()?;
    let client = reqwest::blocking::Client::new();

    // fetch the newsroom verifying key (well clients should pin this)
    let info: NewsroomInfo = client
        .get(format!("{server}/newsroom"))
        .send()
        .with_context(|| format!("fetching {server}/newsroom"))?
        .error_for_status()?
        .json()?;
    let mut vk_nr_bytes = [0u8; 32];
    hex::decode_to_slice(info.verifying_key.trim(), &mut vk_nr_bytes)
        .context("parsing newsroom verifying key")?;
    let vk_nr = VerifyingKey::from_bytes(vk_nr_bytes);

    // send our enrollment to the newsroom
    let request = JournalistSetupRequest {
        enrollment: journalist.enroll(),
    };
    let response: JournalistSetupResponse = client
        .post(format!("{server}/newsroom/journalists/enroll"))
        .json(&request)
        .send()
        .context("posting enrollment")?
        .error_for_status()
        .context("newsroom rejected enrollment")?
        .json()?;

    let vk_j_bytes = (*journalist.signing_key()).into_bytes();
    vk_nr
        .verify(&vk_j_bytes, &response.sig)
        .context("newsroom signature does not verify against the fetched vk_NR")?;

    if let Some(parent) = sig_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&vk_path, &vk_nr_bytes)?;
    write_secret(&sig_path, &response.sig.as_bytes())?;

    println!("Enrolled with newsroom at {server}.\n");
    println!("Newsroom verifying key: {}", hex::encode(vk_nr_bytes));
    println!(
        "Newsroom signature:     {}",
        hex::encode(response.sig.as_bytes())
    );
    Ok(())
}

fn replenish(server: &str, count: usize) -> Result<()> {
    // Journalist has to be enrolled first else we need to bail
    if !newsroom_vk_path()?.exists() {
        bail!("not enrolled yet\nrun `enroll --server <url>` first");
    }

    let mut journalist = load_journalist()?;
    let mut rng = OsRng.unwrap_err();
    journalist.generate_ephemeral_bundles(&mut rng, count);

    let request = journalist.create_ephemeral_key_request();
    let client = reqwest::blocking::Client::new();
    let response: JournalistEphemeralKeyResponse = client
        .post(format!("{server}/newsroom/journalists/keys"))
        .json(&request)
        .send()
        .context("posting ephemeral keys")?
        .error_for_status()
        .context("newsroom rejected ephemeral key replenishment")?
        .json()?;

    // We save the secrets so we can use them later
    append_ephemeral_secrets(&journalist.ephemeral_bundle_bytes())?;

    println!("Uploaded {count} ephemeral key bundles to {server}.\n");
    println!(
        "Server now stores {} ephemeral key bundles for this journalist.",
        response.stored
    );
    Ok(())
}

/// Save ephemeral secrets to disk for later use
fn append_ephemeral_secrets(bundles: &[EphemeralBundleBytes]) -> Result<()> {
    let path = ephemeral_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;

    for bundle in bundles {
        file.write_all(&bundle.as_bytes())?;
    }
    Ok(())
}

fn fetch(server: &str) -> Result<()> {
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
        let text = String::from_utf8_lossy(strip_padding(&plaintext.msg)).into_owned();
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

fn reply(server: &str, message_id: &str, message: &str) -> Result<()> {
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

    let journalists: Vec<SourceJournalistKeyResponse> = client
        .get(format!("{server}/journalists/keys"))
        .send()
        .with_context(|| format!("fetching {server}/journalists/keys"))?
        .error_for_status()
        .context("newsroom rejected journalist key request")?
        .json()?;

    let mut co_journalists = Vec::new();
    for resp in &journalists {
        // Don't reply to ourselves.
        if resp.journalist.verifying_key().into_bytes() == own_vk {
            continue;
        }
        journalist
            .handle_journalist_key_response(resp, &newsroom_vk)
            .context("co-journalist key response failed verification")?;
        co_journalists.push(resp);
    }

    // Send the reply to the source and to every other journalist so they have the convo history
    let mut rng = OsRng.unwrap_err();
    let mut message_ids = Vec::new();
    message_ids.push(send_reply(
        &client,
        server,
        &journalist,
        &source,
        message,
        &mut rng,
    )?);
    for resp in co_journalists {
        message_ids.push(send_reply(
            &client,
            server,
            &journalist,
            &resp.journalist,
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

/// Strip the trailing zero padding applied at submission time.
///
/// TODO: Fix the padding scheme so if a message actually ends in NUL bytes
/// we don't lose data. We should length prefix it instead?
fn strip_padding(msg: &[u8]) -> &[u8] {
    let end = msg.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &msg[..end]
}

/// Load the saved ephemeral secret bundles.
fn load_ephemeral_secrets() -> Result<Vec<EphemeralBundleBytes>> {
    let path = ephemeral_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() % EphemeralBundleBytes::LEN != 0 {
        bail!(
            "{} is corrupt: length {} is not a multiple of {}",
            path.display(),
            bytes.len(),
            EphemeralBundleBytes::LEN
        );
    }
    bytes
        .chunks_exact(EphemeralBundleBytes::LEN)
        .map(EphemeralBundleBytes::from_bytes)
        .collect()
}

fn load_journalist() -> Result<Journalist> {
    let path = long_term_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `init` first)", path.display()))?;
    let parts = JournalistLongTermBytes::from_bytes(&bytes)?;
    Ok(Journalist::from_long_term_bytes(parts))
}

/// Load the newsroom verifying key
fn load_newsroom_vk() -> Result<VerifyingKey> {
    let path = newsroom_vk_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `enroll` first)", path.display()))?;
    let vk_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("newsroom vk is {} bytes, expected 32", v.len()))?;
    Ok(VerifyingKey::from_bytes(vk_bytes))
}

/// Load the locally retained inbox of received messages
fn load_inbox() -> Result<Vec<InboxEntry>> {
    let path = inbox_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Persist the inbox of received messages
fn save_inbox(inbox: &[InboxEntry]) -> Result<()> {
    let path = inbox_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(inbox).context("serializing inbox")?;
    write_secret(&path, &json)
}

fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-journalist")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

fn long_term_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("long-term.bin"))
}

fn ephemeral_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("ephemeral.bin"))
}

fn inbox_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("inbox.json"))
}

fn newsroom_vk_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom-vk.bin"))
}

fn newsroom_sig_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom-sig.bin"))
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    Ok(())
}
