//! Demo source CLI for the SecureDrop protocol.

mod fetch;
mod identity;
mod submit;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "source-cli", about = "Demo SecureDrop source client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Note: The FPF verifying key _would_ be pinned in the client, but here
/// we pass it.
#[derive(Subcommand)]
enum Command {
    /// Generate a new source identity and print its recovery passphrase.
    Generate,
    /// Rederive a source identity from its passphrase and print its public keys.
    Show,
    /// Submit a message to every enrolled journalist of a newsroom.
    Submit {
        /// Newsroom server URL.
        #[arg(long)]
        server: String,
        /// FPF verifying key as 64 hex characters.
        #[arg(long = "fpf-vk")]
        fpf_vk: String,
        /// The message to send.
        #[arg(short, long)]
        message: String,
    },
    /// Fetch and decrypt replies addressed to this source.
    Fetch {
        /// Newsroom server URL.
        #[arg(long)]
        server: String,
        /// FPF verifying key as 64 hex characters.
        #[arg(long = "fpf-vk")]
        fpf_vk: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate => identity::generate(),
        Command::Show => identity::show(),
        Command::Submit {
            server,
            fpf_vk,
            message,
        } => submit::submit(&server, &fpf_vk, &message),
        Command::Fetch { server, fpf_vk } => fetch::fetch(&server, &fpf_vk),
    }
}
