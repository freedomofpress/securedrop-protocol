use anyhow::{Context, Result};
use securedrop_protocol_minimal::{Source, UserPublic};

use crate::util::read_passphrase;

pub(crate) fn generate() -> Result<()> {
    let source = Source::new(rand::rng());
    let mnemonic = source.passphrase();
    let fetch_pk = source.public().fetch_pk().into_bytes();

    println!("New source identity");
    println!();
    println!("Recovery passphrase (write this down!!):");
    println!("  {mnemonic}");
    println!();
    println!("Fetch public key: {}", hex(&fetch_pk));
    Ok(())
}

pub(crate) fn show() -> Result<()> {
    let passphrase = read_passphrase()?;
    let source = Source::from_passphrase(passphrase.trim())
        .context("not a valid BIP39 recovery passphrase")?;
    let fetch_pk = source.public().fetch_pk().into_bytes();

    println!("Fetch public key: {}", hex(&fetch_pk));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
