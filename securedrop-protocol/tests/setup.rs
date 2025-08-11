//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand::rngs::OsRng;

use securedrop_protocol::keys::FPFKeyPair;

/// Step 1: Generate FPF keys
#[test]
fn generate_fpf_keys() {
    let mut rng = OsRng;
    let fpf_keys = FPFKeyPair::new(&mut rng);
    // todo: test serialization / deserialization round trip once we impl that
}

/// Step 2: Generate newsroom keys
#[test]
fn generate_newsroom_keys() {
    let rng = OsRng;
    // todo: fill this out
}
