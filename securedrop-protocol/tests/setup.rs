//! Tests for the setup steps of the protocol.
//! These correspond to steps 1-4 of the spec.

use rand::rng;

use securedrop_protocol::keys::FPFKeyPair;

/// Step 1: Generate FPF keys
#[test]
fn protocol_step_1_generate_fpf_keys() {
    let mut rng = rng();
    let fpf_keys = FPFKeyPair::new(&mut rng);

    // Test signing/verification roundtrip
    let message = b"test message";
    let signature = fpf_keys.sk.sign(message);
    assert!(fpf_keys.vk.verify(message, &signature).is_ok());

    // TODO: test serialization / deserialization round trip once we impl that
}

// /// Step 2: Generate newsroom keys
// #[test]
// fn generate_newsroom_keys() {
//     let rng = OsRng;
//     // todo: fill this out
// }
