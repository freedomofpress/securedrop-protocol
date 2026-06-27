use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use securedrop_protocol_minimal::message::MessagePublicKey;
use securedrop_protocol_minimal::metadata::MetadataPublicKey;
use securedrop_protocol_minimal::primitives::x25519::DHPublicKey;
use securedrop_protocol_minimal::{
    EphemeralBundleBytes, Journalist, JournalistLongTermBytes, VerifyingKey,
};
use serde::{Deserialize, Serialize};

/// A received message retained locally after `fetch` deletes it from the server.
///
/// Stores the decrypted text and the source's recovered reply keys
/// (so reply can encrypt back to them without DLing from the server,
/// because the server no longer has the message).
#[derive(Serialize, Deserialize)]
pub(crate) struct InboxEntry {
    pub(crate) message_id: String,
    pub(crate) text: String,
    pub(crate) sender_fetch_pk: DHPublicKey,
    pub(crate) sender_apke_pk: MessagePublicKey,
    pub(crate) sender_metadata_pk: MetadataPublicKey,
}

pub(crate) fn load_journalist() -> Result<Journalist> {
    let path = long_term_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `init` first)", path.display()))?;
    let parts = JournalistLongTermBytes::from_bytes(&bytes)?;
    Ok(Journalist::from_long_term_bytes(parts))
}

/// Load the newsroom verifying key
pub(crate) fn load_newsroom_vk() -> Result<VerifyingKey> {
    let path = newsroom_vk_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `enroll` first)", path.display()))?;
    let vk_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("newsroom vk is {} bytes, expected 32", v.len()))?;
    Ok(VerifyingKey::from_bytes(vk_bytes))
}

/// Load the saved ephemeral secret bundles.
pub(crate) fn load_ephemeral_secrets() -> Result<Vec<EphemeralBundleBytes>> {
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

/// Save ephemeral secrets to disk for later use
pub(crate) fn append_ephemeral_secrets(bundles: &[EphemeralBundleBytes]) -> Result<()> {
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

/// Load the locally retained inbox of received messages
pub(crate) fn load_inbox() -> Result<Vec<InboxEntry>> {
    let path = inbox_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// Persist the inbox of received messages
pub(crate) fn save_inbox(inbox: &[InboxEntry]) -> Result<()> {
    let path = inbox_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(inbox).context("serializing inbox")?;
    write_secret(&path, &json)
}

pub(crate) fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-journalist")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

pub(crate) fn long_term_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("long-term.bin"))
}

pub(crate) fn ephemeral_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("ephemeral.bin"))
}

pub(crate) fn inbox_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("inbox.json"))
}

pub(crate) fn newsroom_vk_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom-vk.bin"))
}

pub(crate) fn newsroom_sig_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom-sig.bin"))
}

pub(crate) fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    Ok(())
}
