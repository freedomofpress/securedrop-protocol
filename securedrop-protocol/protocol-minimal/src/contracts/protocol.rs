pub(crate) struct ProtocolError;

/// Protocol operations available to all users.
pub trait ClientProtocol {
    type CryptoProvider: crypto_provider::CryptoProvider;
    todo!("unimplemented");

}

/// Protocol operations additionally available to journalists.
pub trait JournalistClientProtocol: ClientProtocol {
    todo!("unimplemented");

}


/// Server protocol operations
pub trait ServerProtocol {

    type CryptoProvider: crypto_provider::CryptoProvider;

    // Verify signature (FPF key over NR key, NR over journalist long-term keys)
    todo!("unimplemented");

    // Generate all fetch challenges
    todo!("unimplemented");

    // Generate single fetch challenge
    todo!("unimplemented");

    // Generate (ristretto255) keypair
    todo!("unimplemented");

    // compute ec point
    todo!("unimplemented");

}

