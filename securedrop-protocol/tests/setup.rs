use rand::OsRng;

use securedrop_protocol::keys::FPFKeyPair;

/// Step 1: Generate FPF keys
#[test]
fn generate_fpf_keys() {
    let rng = OsRng;
    let fpf_keys = FPFKeyPair::new(&mut rng);
    // todo: test serialization / deserialization round trip once we impl that
}

/// Step 2: Generate newsroom keys
#[test]
fn generate_newsroom_keys() {
    let rng = OsRng;
    // todo: fill this out
}
