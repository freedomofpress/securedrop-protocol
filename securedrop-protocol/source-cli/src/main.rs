//! Demo source CLI for the SecureDrop protocol.

use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::{Source, UserPublic};

#[derive(Parser)]
#[command(name = "source-cli", about = "Demo SecureDrop source client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new source identity and print its recovery passphrase.
    Generate,
    /// Rederive a source identity from its passphrase and print its public keys.
    Show,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate => generate(),
        Command::Show => show(),
    }
}

fn generate() -> Result<()> {
    let source = Source::new(OsRng.unwrap_err());
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

fn show() -> Result<()> {
    let passphrase = read_passphrase()?;
    let source = Source::from_passphrase(passphrase.trim())
        .context("not a valid BIP39 recovery passphrase")?;
    let fetch_pk = source.public().fetch_pk().into_bytes();

    println!("Fetch public key: {}", hex(&fetch_pk));
    Ok(())
}

/// Obtain the source passphrase without persisting it: prefer the
/// `SOURCE_PASSPHRASE` environment variable, otherwise prompt on stdin.
fn read_passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("SOURCE_PASSPHRASE") {
        if !p.trim().is_empty() {
            return Ok(p);
        }
    }
    if io::stdin().is_terminal() {
        eprint!("Enter source passphrase: ");
        io::stderr().flush().ok();
    }
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("reading passphrase from stdin")?;
    Ok(line)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
