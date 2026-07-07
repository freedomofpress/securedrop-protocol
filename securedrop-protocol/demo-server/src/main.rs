//! Demo SecureDrop protocol server.

mod fpf;
mod newsroom;
mod state;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Run the newsroom HTTP server.
    Start {
        /// Port to listen on.
        #[arg(long, default_value_t = 8000)]
        port: u16,
    },
}

fn main() -> Result<()> {
    match Cli::parse().role {
        Role::Fpf { action } => match action {
            FpfAction::Init { force } => fpf::init(force),
            FpfAction::SignNewsroom { vk } => fpf::sign_newsroom(&vk),
            FpfAction::ShowVk => fpf::show_vk(),
        },
        Role::Newsroom { action } => match action {
            NewsroomAction::Init { force } => newsroom::init(force),
            NewsroomAction::ShowVk => newsroom::show_vk(),
            NewsroomAction::SetFpfSig { sig, fpf_vk, force } => {
                newsroom::set_fpf_sig(&sig, &fpf_vk, force)
            }
            NewsroomAction::Start { port } => newsroom::start(port),
        },
    }
}
