//! Demo SecureDrop journalist client.

mod fetch;
mod reply;
mod setup;
mod storage;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Generate fresh ephemeral key bundles and upload them to the server.
    Replenish {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
        /// Number of ephemeral key bundles to generate and upload.
        #[arg(long, default_value_t = 10)]
        count: usize,
    },
    /// Fetch and decrypt messages addressed to this journalist.
    Fetch {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
    },
    /// Reply to a source message (identified by its message ID from `fetch`).
    Reply {
        /// Newsroom server URL, e.g. `http://localhost:8000`.
        #[arg(long)]
        server: String,
        /// The message ID to reply to, as printed by `fetch`.
        #[arg(long = "message-id")]
        message_id: String,
        /// The reply text to send.
        #[arg(short, long)]
        message: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { force } => setup::init(force),
        Command::Enroll { server, force } => setup::enroll(&server, force),
        Command::Replenish { server, count } => setup::replenish(&server, count),
        Command::Fetch { server } => fetch::fetch(&server),
        Command::Reply {
            server,
            message_id,
            message,
        } => reply::reply(&server, &message_id, &message),
    }
}
