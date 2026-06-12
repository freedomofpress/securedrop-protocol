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
use securedrop_protocol_minimal::keys::{FPFKeyPair, NewsroomKeyPair};
use securedrop_protocol_minimal::wire::setup::NewsroomSetupRequest;
use securedrop_protocol_minimal::{FpfOnNewsroom, Signature, VerifyingKey};

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
    /// Print the FPF verifying key as 64 hex characters on stdout.
    ShowVk,
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
    /// Store the FPF signature over the newsroom verifying key (128 hex characters).
    ///
    /// The signature is verified against the supplied FPF verifying key and the
    /// on-disk newsroom verifying key before being persisted.
    SetFpfSig {
        /// FPF signature as 128 hex characters.
        sig: String,
        /// FPF verifying key as 64 hex characters (pinned into the newsroom).
        #[arg(long = "fpf-vk")]
        fpf_vk: String,
        /// Overwrite an existing stored FPF signature.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().role {
        Role::Fpf { action } => match action {
            FpfAction::Init { force } => fpf_init(force),
            FpfAction::SignNewsroom { vk } => fpf_sign_newsroom(&vk),
            FpfAction::ShowVk => fpf_show_vk(),
        },
        Role::Newsroom { action } => match action {
            NewsroomAction::Init { force } => newsroom_init(force),
            NewsroomAction::ShowVk => newsroom_show_vk(),
            NewsroomAction::SetFpfSig { sig, fpf_vk, force } => {
                newsroom_set_fpf_sig(&sig, &fpf_vk, force)
            }
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
    hex::decode_to_slice(vk_hex.trim(), &mut vk_bytes).context("parsing newsroom verifying key")?;
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

fn fpf_show_vk() -> Result<()> {
    let kp = load_fpf_keypair()?;
    println!("{}", hex::encode(kp.verifying_key().into_bytes()));
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

fn newsroom_set_fpf_sig(sig_hex: &str, fpf_vk_hex: &str, force: bool) -> Result<()> {
    let mut sig_bytes = [0u8; 64];
    hex::decode_to_slice(sig_hex.trim(), &mut sig_bytes).context("parsing FPF signature")?;
    let mut fpf_vk_bytes = [0u8; 32];
    hex::decode_to_slice(fpf_vk_hex.trim(), &mut fpf_vk_bytes)
        .context("parsing FPF verifying key")?;

    let path = fpf_sig_path()?;
    if path.exists() && !force {
        bail!(
            "an FPF signature already exists at {}\nuse `newsroom set-fpf-sig --force` to overwrite it",
            path.display()
        );
    }

    let nr_kp = load_newsroom_keypair()?;
    let vk_nr_bytes = nr_kp.verifying_key().into_bytes();
    let vk_fpf = VerifyingKey::from_bytes(fpf_vk_bytes);
    let sig = Signature::<FpfOnNewsroom>::from_bytes(sig_bytes);

    vk_fpf
        .verify(&vk_nr_bytes, &sig)
        .context("FPF signature does not verify against this newsroom's verifying key")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &sig_bytes)?;

    println!("FPF signature verified and stored.\n");
    println!("Saved to: {}", path.display());
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

fn fpf_sig_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("fpf-sig.bin"))
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
