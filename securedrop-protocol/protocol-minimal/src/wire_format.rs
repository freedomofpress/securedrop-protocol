use alloc::vec::Vec;

use crate::ciphertext::Plaintext;

const LEN_REPLY_PUBKEY: usize = 1216;
const LEN_FETCH_KEY: usize = 32;

const PREFIX_LEN: usize = LEN_REPLY_PUBKEY + LEN_FETCH_KEY;

#[cfg(not(hax))]
const _: () = {
    assert!(LEN_REPLY_PUBKEY == crate::primitives::xwing::XWING_PUBLIC_KEY_LEN);
    assert!(LEN_FETCH_KEY == crate::primitives::x25519::DH_PUBLIC_KEY_LEN);
};

pub const TAG_V0: u8 = 0x00;
pub const TAG_V1: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    UnknownVersion,
    TooShort,
    RoundTripFailed,
    NonCanonical,
}

pub fn version_tag(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes[0])
    }
}

pub const MAX_MSG_LEN: usize = usize::MAX - PREFIX_LEN - 1;

// [Theorem] Proves: the encoded length never overflows `usize`, so `serialize_v0` is panic-free.
#[cfg_attr(hax, hax_lib::requires(p.msg.len() <= MAX_MSG_LEN))]
pub fn serialize_v0(p: &Plaintext) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(TAG_V0);
    buf.extend_from_slice(&p.sender_reply_pubkey_hybrid);
    buf.extend_from_slice(&p.sender_fetch_key);
    buf.extend_from_slice(&p.msg);
    buf
}

fn deserialize_v0_body(body: &[u8]) -> Result<Plaintext, WireError> {
    if body.len() < PREFIX_LEN {
        return Err(WireError::TooShort);
    }

    let mut sender_reply_pubkey_hybrid = [0u8; LEN_REPLY_PUBKEY];
    sender_reply_pubkey_hybrid.copy_from_slice(&body[0..LEN_REPLY_PUBKEY]);

    let mut sender_fetch_key = [0u8; LEN_FETCH_KEY];
    sender_fetch_key.copy_from_slice(&body[LEN_REPLY_PUBKEY..PREFIX_LEN]);

    let msg = body[PREFIX_LEN..].to_vec();

    Ok(Plaintext {
        sender_reply_pubkey_hybrid,
        sender_fetch_key,
        msg,
    })
}

// [Theorem] Proves: the encoded length never overflows `usize`, so `serialize_v1` is panic-free.
#[cfg_attr(hax, hax_lib::requires(p.msg.len() <= MAX_MSG_LEN))]
pub fn serialize_v1(p: &Plaintext) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(TAG_V1);
    buf.extend_from_slice(&p.sender_fetch_key);
    buf.extend_from_slice(&p.sender_reply_pubkey_hybrid);
    buf.extend_from_slice(&p.msg);
    buf
}

fn deserialize_v1_body(body: &[u8]) -> Result<Plaintext, WireError> {
    if body.len() < PREFIX_LEN {
        return Err(WireError::TooShort);
    }

    let mut sender_fetch_key = [0u8; LEN_FETCH_KEY];
    sender_fetch_key.copy_from_slice(&body[0..LEN_FETCH_KEY]);

    let mut sender_reply_pubkey_hybrid = [0u8; LEN_REPLY_PUBKEY];
    sender_reply_pubkey_hybrid.copy_from_slice(&body[LEN_FETCH_KEY..PREFIX_LEN]);

    let msg = body[PREFIX_LEN..].to_vec();

    Ok(Plaintext {
        sender_reply_pubkey_hybrid,
        sender_fetch_key,
        msg,
    })
}

// [Theorem] Proves: the call to `serialize_v0` cannot overflow (its precondition holds here).
#[cfg_attr(hax, hax_lib::requires(p.msg.len() <= MAX_MSG_LEN))]
// [Guarded] Proves (round-trip): whenever `serialize` returns `Ok(buf)`, `deserialize(buf)` recovers `p`.
#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Ok(buf) => deserialize(&buf) == Ok(p.clone()),
    Err(_) => true,
}))]
pub fn serialize(p: &Plaintext) -> Result<Vec<u8>, WireError> {
    let buf = serialize_v0(p);
    if deserialize(&buf) == Ok(p.clone()) {
        Ok(buf)
    } else {
        Err(WireError::RoundTripFailed)
    }
}

// [Guarded] Proves (non-malleability): whenever `deserialize` returns `Ok(p)`, re-encoding `p` reproduces the input bytes exactly.
#[cfg_attr(hax, hax_lib::ensures(|result| match result {
    Ok(p) => p.msg.len() <= MAX_MSG_LEN && serialize_v0(&p).as_slice() == bytes,
    Err(_) => true,
}))]
pub fn deserialize(bytes: &[u8]) -> Result<Plaintext, WireError> {
    let p = match version_tag(bytes) {
        Some(TAG_V0) => deserialize_v0_body(&bytes[1..])?,
        _ => return Err(WireError::UnknownVersion),
    };
    if p.msg.len() <= MAX_MSG_LEN && serialize_v0(&p).as_slice() == bytes {
        Ok(p)
    } else {
        Err(WireError::NonCanonical)
    }
}

pub fn deserialize_versioned(bytes: &[u8]) -> Result<Plaintext, WireError> {
    match version_tag(bytes) {
        Some(TAG_V0) => deserialize_v0_body(&bytes[1..]),
        Some(TAG_V1) => deserialize_v1_body(&bytes[1..]),
        _ => Err(WireError::UnknownVersion),
    }
}

// [Theorem] Proves (injective versioning): every V0 encoding begins with tag `TAG_V0`, for all records.
#[cfg(hax)]
#[hax_lib::lemma]
fn lemma_version_tag_v0(
    p: Plaintext,
) -> Proof<{ p.msg.len() > MAX_MSG_LEN || version_tag(&serialize_v0(&p)) == Some(TAG_V0) }> {
}

// [Theorem] Proves (injective versioning): every V1 encoding begins with tag `TAG_V1`, for all records (and `TAG_V0 != TAG_V1`, so versions never collide).
#[cfg(hax)]
#[hax_lib::lemma]
fn lemma_version_tag_v1(
    p: Plaintext,
) -> Proof<{ p.msg.len() > MAX_MSG_LEN || version_tag(&serialize_v1(&p)) == Some(TAG_V1) }> {
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn plaintext_strategy() -> impl Strategy<Value = Plaintext> {
        (
            proptest::array::uniform(any::<u8>()).prop_map(|a: [u8; LEN_REPLY_PUBKEY]| a),
            proptest::array::uniform(any::<u8>()).prop_map(|a: [u8; LEN_FETCH_KEY]| a),
            proptest::collection::vec(any::<u8>(), 0..256),
        )
            .prop_map(
                |(sender_reply_pubkey_hybrid, sender_fetch_key, msg)| Plaintext {
                    sender_reply_pubkey_hybrid,
                    sender_fetch_key,
                    msg,
                },
            )
    }

    proptest! {
        // Tests (round-trip): on sampled records, `serialize` succeeds and `deserialize` recovers the record.
        #[test]
        fn prop_roundtrip(p in plaintext_strategy()) {
            let bytes = serialize(&p).expect("serialize must succeed for a valid record");
            let decoded = deserialize(&bytes).expect("valid V0 encoding must decode");
            prop_assert_eq!(decoded, p);
        }

        // Tests (non-malleability): on sampled byte strings, any that decode re-encode back to themselves.
        #[test]
        fn prop_non_malleable(m in proptest::collection::vec(any::<u8>(), 0..(PREFIX_LEN + 256))) {
            if let Ok(p) = deserialize(&m) {
                prop_assert_eq!(serialize_v0(&p), m);
            }
        }

        // Tests (injective versioning): on sampled records, each encoder stamps its own distinct tag.
        #[test]
        fn prop_version_tags(p in plaintext_strategy()) {
            prop_assert_eq!(version_tag(&serialize_v0(&p)), Some(TAG_V0));
            prop_assert_eq!(version_tag(&serialize_v1(&p)), Some(TAG_V1));
            prop_assert_ne!(TAG_V0, TAG_V1);
        }
    }
}
