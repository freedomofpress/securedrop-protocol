use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use axum::{Router, routing::get};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::keys::NewsroomKeyPair;
use securedrop_protocol_minimal::{FpfOnNewsroom, Signature, VerifyingKey};

use crate::state::{data_dir, write_secret};

pub fn init(force: bool) -> Result<()> {
    let path = key_path()?;
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

pub fn show_vk() -> Result<()> {
    let kp = load_keypair()?;
    println!("{}", hex::encode(kp.verifying_key().into_bytes()));
    Ok(())
}

pub fn set_fpf_sig(sig_hex: &str, fpf_vk_hex: &str, force: bool) -> Result<()> {
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

    let nr_kp = load_keypair()?;
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

pub fn start(port: u16) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    rt.block_on(serve(port))
}

async fn serve(port: u16) -> Result<()> {
    let app = Router::new().route("/", get(|| async { "securedrop newsroom (demo)\n" }));
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding to {addr}"))?;
    println!("Newsroom server listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install ctrl-c handler");
    println!("\nShutting down.");
}

fn load_keypair() -> Result<NewsroomKeyPair> {
    let path = key_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `newsroom init` first)", path.display()))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("{} is {} bytes, expected 32", path.display(), v.len())
    })?;
    Ok(NewsroomKeyPair::from_bytes(seed))
}

fn key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("newsroom.key"))
}

fn fpf_sig_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("fpf-sig.bin"))
}
