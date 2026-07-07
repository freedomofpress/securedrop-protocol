use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use securedrop_protocol_minimal::VerifyingKey;
use securedrop_protocol_minimal::keys::FPFKeyPair;
use securedrop_protocol_minimal::wire::setup::NewsroomSetupRequest;

use crate::state::{data_dir, write_secret};

pub fn init(force: bool) -> Result<()> {
    let path = key_path()?;
    if path.exists() && !force {
        bail!(
            "an FPF key already exists at {}\nuse `fpf init --force` to overwrite it",
            path.display()
        );
    }

    let kp = FPFKeyPair::new(&mut rand::rng()).context("generating FPF keypair")?;
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

pub fn sign_newsroom(vk_hex: &str) -> Result<()> {
    let mut vk_bytes = [0u8; 32];
    hex::decode_to_slice(vk_hex.trim(), &mut vk_bytes).context("parsing newsroom verifying key")?;
    let fpf_kp = load_keypair()?;

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

pub fn show_vk() -> Result<()> {
    let kp = load_keypair()?;
    println!("{}", hex::encode(kp.verifying_key().into_bytes()));
    Ok(())
}

fn load_keypair() -> Result<FPFKeyPair> {
    let path = key_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `fpf init` first)", path.display()))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("{} is {} bytes, expected 32", path.display(), v.len())
    })?;
    Ok(FPFKeyPair::from_bytes(seed))
}

fn key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("fpf").join("fpf.key"))
}
