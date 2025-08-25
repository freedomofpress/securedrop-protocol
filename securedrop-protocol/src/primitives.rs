// TODO(ro): Import whatever crate provides the appropriate keys

// TODO(ro): Fill in types here

#[derive(Debug, Clone)]
pub struct PPKPrivateKey;

#[derive(Debug, Clone)]
pub struct PPKPublicKey;

impl PPKPublicKey {
    pub fn into_bytes(self) -> [u8; 32] {
        // TODO: Implement when actual PPK types are available
        [0u8; 32]
    }
}

#[derive(Debug, Clone)]
pub struct DHPublicKey;

impl DHPublicKey {
    pub fn into_bytes(self) -> [u8; 32] {
        // TODO: Implement when actual DH types are available
        [0u8; 32]
    }
}

#[derive(Debug, Clone)]
pub struct DHPrivateKey;
