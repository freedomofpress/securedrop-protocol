
// WIP - Each module exposes their own error type

#[derive(Debug)]
pub enum Error {
    Api(client::NetworkError),
    Protocol(protocol::ProtocolError),
    CryptoProvider(crypto_provider::CryptoProviderError),
}
