use std::io::{self, IsTerminal, Write};

use anyhow::{Context, Result};
use securedrop_protocol_minimal::VerifyingKey;
use securedrop_protocol_minimal::keys::Timestamp;

/// Obtain the source passphrase without persisting it: prefer the
/// `SOURCE_PASSPHRASE` environment variable, otherwise prompt on stdin.
pub(crate) fn read_passphrase() -> Result<String> {
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

pub(crate) fn parse_fpf_vk(fpf_vk_hex: &str) -> Result<VerifyingKey> {
    let mut fpf_vk_bytes = [0u8; VerifyingKey::LEN];
    hex::decode_to_slice(fpf_vk_hex.trim(), &mut fpf_vk_bytes)
        .context("parsing FPF verifying key")?;
    Ok(VerifyingKey::from_bytes(fpf_vk_bytes))
}

/// Current wall-clock time as seconds since the Unix epoch.
pub(crate) fn now() -> Timestamp {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs();
    Timestamp(secs)
}
