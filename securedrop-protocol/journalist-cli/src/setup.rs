use std::fs;

use anyhow::{Context, Result, bail};
use securedrop_protocol_minimal::api::JournalistApi;
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyResponse, JournalistSetupRequest, JournalistSetupResponse,
};
use securedrop_protocol_minimal::{Enrollable, Journalist, VerifyingKey};
use serde::Deserialize;

use crate::storage::{
    append_ephemeral_secrets, load_journalist, long_term_path, newsroom_sig_path, newsroom_vk_path,
    write_secret,
};

#[derive(Deserialize)]
struct NewsroomInfo {
    verifying_key: String,
}

pub(crate) fn init(force: bool) -> Result<()> {
    let path = long_term_path()?;
    if path.exists() && !force {
        bail!(
            "a journalist key already exists at {}\nuse `init --force` to overwrite it",
            path.display()
        );
    }

    let mut rng = rand::rng();
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

pub(crate) fn enroll(server: &str, force: bool) -> Result<()> {
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

pub(crate) fn replenish(server: &str, count: usize) -> Result<()> {
    // Journalist has to be enrolled first else we need to bail
    if !newsroom_vk_path()?.exists() {
        bail!("not enrolled yet\nrun `enroll --server <url>` first");
    }

    let mut journalist = load_journalist()?;
    let mut rng = rand::rng();
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
