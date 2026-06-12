//! Demo SecureDrop protocol server.
//!
//! Right now this also has an FPF subcommand for generating the
//! FPF signing keypair for testing.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::VerifyingKey;
use securedrop_protocol_minimal::keys::{FPFKeyPair, NewsroomKeyPair};
use securedrop_protocol_minimal::wire::setup::NewsroomSetupRequest;

#[derive(Parser)]
#[command(name = "demo-server", about = "Demo SecureDrop protocol server")]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// FPF root-of-trust operations.
    Fpf {
        #[command(subcommand)]
        action: FpfAction,
    },
    /// Newsroom operations.
    Newsroom {
        #[command(subcommand)]
        action: NewsroomAction,
    },
}

#[derive(Subcommand)]
enum FpfAction {
    /// Generate the FPF signing keypair and persist it.
    Init {
        /// Overwrite an existing FPF key.
        #[arg(long)]
        force: bool,
    },
    /// Sign a newsroom verifying key (32-byte hex).
    SignNewsroom {
        /// Newsroom verifying key as 64 hex characters.
        vk: String,
    },
}

#[derive(Subcommand)]
enum NewsroomAction {
    /// Generate the newsroom signing keypair and persist it.
    Init {
        /// Overwrite an existing newsroom key.
        #[arg(long)]
        force: bool,
    },
    /// Print the newsroom verifying key as 64 hex characters on stdout.
    ShowVk,
}

fn main() -> Result<()> {
    match Cli::parse().role {
        Role::Fpf { action } => match action {
            FpfAction::Init { force } => fpf_init(force),
            FpfAction::SignNewsroom { vk } => fpf_sign_newsroom(&vk),
        },
        Role::Newsroom { action } => match action {
            NewsroomAction::Init { force } => newsroom_init(force),
            NewsroomAction::ShowVk => newsroom_show_vk(),
        },
    }
}

fn fpf_init(force: bool) -> Result<()> {
    let path = fpf_key_path()?;
    if path.exists() && !force {
        bail!(
            "an FPF key already exists at {}\nuse `fpf init --force` to overwrite it",
            path.display()
        );
    }

    let kp = FPFKeyPair::new(OsRng.unwrap_err()).context("generating FPF keypair")?;
    let seed = kp.as_bytes();
    let vk = kp.verifying_key().into_bytes();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &seed)?;

    println!("FPF root of trust initialized.\n");
    println!("Saved to:           {}", path.display());
    println!("FPF verifying key:  {}\n", hex::encode(vk));
    println!("Pin this verifying key into source and journalist clients.");
    Ok(())
}

fn fpf_sign_newsroom(vk_hex: &str) -> Result<()> {
    let mut vk_bytes = [0u8; 32];
    hex::decode_to_slice(vk_hex.trim(), &mut vk_bytes)
        .context("parsing newsroom verifying key")?;
    let fpf_kp = load_fpf_keypair()?;

    let req = NewsroomSetupRequest {
        newsroom_verifying_key: VerifyingKey::from_bytes(vk_bytes),
    };
    let resp = req
        .sign(&fpf_kp)
        .context("signing newsroom verifying key")?;
    let sig = resp.sig.as_bytes();

    // Dump signature to stdout
    println!("{}", hex::encode(sig));
    Ok(())
}

fn load_fpf_keypair() -> Result<FPFKeyPair> {
    let path = fpf_key_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `fpf init` first)", path.display()))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("{} is {} bytes, expected 32", path.display(), v.len())
    })?;
    Ok(FPFKeyPair::from_bytes(seed))
}

fn newsroom_init(force: bool) -> Result<()> {
    let path = newsroom_key_path()?;
    if path.exists() && !force {
        bail!(
            "a newsroom key already exists at {}\nuse `newsroom init --force` to overwrite it",
            path.display()
        );
    }

    let kp = NewsroomKeyPair::new(OsRng.unwrap_err()).context("generating newsroom keypair")?;
    let seed = kp.as_bytes();
    let vk = kp.verifying_key().into_bytes();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &seed)?;

    println!("Newsroom signing key generated.\n");
    println!("Saved to:               {}", path.display());
    println!("Newsroom verifying key: {}\n", hex::encode(vk));
    println!("Hand this verifying key to FPF for signing.");
    Ok(())
}

fn newsroom_show_vk() -> Result<()> {
    let kp = load_newsroom_keypair()?;
    println!("{}", hex::encode(kp.verifying_key().into_bytes()));
    Ok(())
}

fn load_newsroom_keypair() -> Result<NewsroomKeyPair> {
    let path = newsroom_key_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `newsroom init` first)", path.display()))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("{} is {} bytes, expected 32", path.display(), v.len())
    })?;
    Ok(NewsroomKeyPair::from_bytes(seed))
}

fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-demo-server")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

fn fpf_key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("fpf").join("fpf.key"))
}

fn newsroom_key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("newsroom.key"))
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
