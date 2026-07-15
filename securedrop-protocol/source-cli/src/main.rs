//! Demo source CLI for the SecureDrop protocol.

mod fetch;
mod identity;
mod state;
mod submit;
mod util;

use std::io::{self, Write};

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::state::State;

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
    ShowSelf,
    /// Submit a message to every enrolled journalist of a newsroom.
    Submit {
        /// Newsroom server URL.
        #[arg(long, default_value = "http://127.0.0.1:8000")]
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
        #[arg(long, default_value = "http://127.0.0.1:8000")]
        server: String,
        /// FPF verifying key as 64 hex characters.
        #[arg(long = "fpf-vk")]
        fpf_vk: String,
    },
    /// Show everything the source has access to (in-memory state).
    /// This corresponds to the information that is available to display
    /// in the UI for a given source.
    ShowState {},
    Exit {},
}

fn main() -> Result<()> {
    let mut in_memory_state: State = State::new();

    println!("SecureDrop Protocol Source demo");
    println!("(actions: generate, show-self, submit, fetch, show-state, help, exit)");

    loop {
        print!("source> ");
        io::stdout().flush()?;

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        // parse shell quotes
        let argv = match shlex::split(line) {
            Some(mut args) => {
                args.insert(0, "source-cli".to_string());
                args
            }
            None => {
                eprintln!("Could not parse command");
                continue;
            }
        };

        let cli = match Cli::try_parse_from(argv) {
            Ok(cli) => cli,
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        };

        let result = match cli.command {
            Command::Generate => {
                let s = state::SourcePretty(identity::generate()?);
                in_memory_state.source = Some(s);

                Ok(())
            }
            Command::ShowSelf => identity::show(),
            Command::Submit {
                server,
                fpf_vk,
                message,
            } => {
                in_memory_state.fpf_vk = Some(fpf_vk.clone());
                in_memory_state.server = Some(server.clone());

                submit::submit(&server, &fpf_vk, &message)
            }
            Command::Fetch { server, fpf_vk } => fetch::fetch(&server, &fpf_vk),
            Command::ShowState {} => in_memory_state.show_state(),
            Command::Exit {} => break,
        };

        if let Err(err) = result {
            eprintln!("{err}");
        }
    }
    Ok(())
}
