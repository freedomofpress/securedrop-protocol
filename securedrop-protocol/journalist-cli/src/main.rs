//! Demo SecureDrop journalist client.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::wire::setup::{JournalistSetupRequest, JournalistSetupResponse};
use securedrop_protocol_minimal::{Enrollable, Journalist, JournalistLongTermBytes, VerifyingKey};
use serde::Deserialize;

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
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { force } => init(force),
        Command::Enroll { server, force } => enroll(&server, force),
    }
}

#[derive(Deserialize)]
struct NewsroomInfo {
    verifying_key: String,
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

fn load_journalist() -> Result<Journalist> {
    let path = long_term_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `init` first)", path.display()))?;
    let parts = JournalistLongTermBytes::from_bytes(&bytes)?;
    Ok(Journalist::from_long_term_bytes(parts))
}

fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-journalist")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

fn long_term_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("long-term.bin"))
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
