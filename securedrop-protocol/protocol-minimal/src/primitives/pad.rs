/// Fixed-length padded message length.
///
/// Note: I made this up. We should pick something based on actual reasons.
use crate::size::PLAINTEXT_WIRE_MAX_PADDED_SIZE;

/// Pad a message to a fixed length.
///
/// # Panics
///
/// Panics if `message` is longer than `PADDED_MESSAGE_LEN`. The verification
/// precondition (`requires`) rules this out, so the panic is provably
/// unreachable and the length subtraction is safe.
#[cfg_attr(hax, hax_lib::requires(message.len() <= PLAINTEXT_WIRE_MAX_PADDED_SIZE))]
pub fn pad_message(message: &[u8]) -> [u8; PLAINTEXT_WIRE_MAX_PADDED_SIZE] {
    if message.len() > PLAINTEXT_WIRE_MAX_PADDED_SIZE {
        panic!("Message too long for padding");
    }

    let mut padded: [u8; PLAINTEXT_WIRE_MAX_PADDED_SIZE] = [0u8; PLAINTEXT_WIRE_MAX_PADDED_SIZE];
    padded[0..message.len()].copy_from_slice(message);

    padded
}
