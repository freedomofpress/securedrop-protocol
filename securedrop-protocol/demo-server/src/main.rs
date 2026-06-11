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
use securedrop_protocol_minimal::keys::FPFKeyPair;

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
}

#[derive(Subcommand)]
enum FpfAction {
    /// Generate the FPF signing keypair and persist it.
    Init {
        /// Overwrite an existing FPF key.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().role {
        Role::Fpf { action } => match action {
            FpfAction::Init { force } => fpf_init(force),
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
    println!("FPF verifying key:  {}\n", hex(&vk));
    println!("Pin this verifying key into source and journalist clients.");
    Ok(())
}

fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-demo-server")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

fn fpf_key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("fpf").join("fpf.key"))
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
