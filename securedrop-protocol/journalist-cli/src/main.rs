//! Demo SecureDrop journalist client.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::{
    Enrollable, Journalist, JournalistLongTermBytes, MLKEM768_PRIVATE_KEY_LEN,
    MLKEM768_PUBLIC_KEY_LEN,
};

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
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { force } => init(force),
    }
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
    let bytes = serialize_long_term(&journalist.long_term_bytes());

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &bytes)?;

    println!("Saved to:                 {}", path.display());
    println!("Journalist verifying key: {}\n", hex::encode(vk));
    println!("Hand this verifying key to the newsroom for signing.");
    Ok(())
}

// Eventually move this into the protocol crate. Trying to keep the conflicts to a minimum.
fn serialize_long_term(parts: &JournalistLongTermBytes) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(32 + 32 + 32 + MLKEM768_PRIVATE_KEY_LEN + MLKEM768_PUBLIC_KEY_LEN);
    buf.extend_from_slice(&parts.sig_seed);
    buf.extend_from_slice(&parts.fetch_sk);
    buf.extend_from_slice(&parts.apke_dhakem_sk);
    buf.extend_from_slice(&parts.apke_mlkem_sk);
    buf.extend_from_slice(&parts.apke_mlkem_pk);
    buf
}

fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-journalist")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

fn long_term_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("long-term.bin"))
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
