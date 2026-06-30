use alloc::vec::Vec;

/// Fixed-length padded message length.
///
/// Note: I made this up. We should pick something based on actual reasons.
pub const PADDED_MESSAGE_LEN: usize = 100000;

/// Pad a message to a fixed length.
///
/// # Panics
///
/// Panics if `message` is longer than `PADDED_MESSAGE_LEN`. The verification
/// precondition (`requires`) rules this out, so the panic is provably
/// unreachable and the length subtraction is safe.
#[cfg_attr(hax, hax_lib::requires(message.len() <= PADDED_MESSAGE_LEN))]
pub fn pad_message(message: &[u8]) -> Vec<u8> {
    if message.len() > PADDED_MESSAGE_LEN {
        panic!("Message too long for padding");
    }

    let mut padded = Vec::with_capacity(PADDED_MESSAGE_LEN);
    padded.extend_from_slice(message);

    // Append zeros to reach the fixed length.
    let padding = alloc::vec![0u8; PADDED_MESSAGE_LEN - message.len()];
    padded.extend_from_slice(&padding);

    padded
}
