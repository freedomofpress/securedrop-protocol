use alloc::vec::Vec;

/// Fixed-length padded message length.
///
/// Note: I made this up. We should pick something based on actual reasons.
pub const PADDED_MESSAGE_LEN: usize = 1024;

/// Pad a message to a fixed length
pub fn pad_message(message: &[u8]) -> Vec<u8> {
    if message.len() > PADDED_MESSAGE_LEN {
        // TODO: Handle message truncation or error outside of this function
        panic!("Message too long for padding");
    }

    let mut padded = Vec::with_capacity(PADDED_MESSAGE_LEN);
    padded.extend_from_slice(message);

    // Pad with zeros to reach the fixed length
    let padding_needed = PADDED_MESSAGE_LEN - message.len();
    for _ in 0..padding_needed {
        padded.push(0u8);
    }

    padded
}
