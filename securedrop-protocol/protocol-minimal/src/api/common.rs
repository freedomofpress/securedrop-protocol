use rand_core::CryptoRng;
use rand_core::RngCore;

/// Any implementing application must have a suitable randomness source
pub trait HasRng {
    type Rng: CryptoRng + RngCore;
    // Todo: we may decide on another implementation pattern that doesn't expose
    // the rng to downstream implementors, for example an Application<R: Rng> struct
    // that takes the rng as a parameter.
    // This approach allows downstream implementors to define their own application struct,
    // but exposes the fn rng().
    #[doc(hidden)]
    fn rng(&mut self) -> &mut Self::Rng;
}

// Stub, handle untrusted input, eg via `sanitize(in: Untrusted<T>) -> T` function
pub struct Untrusted<T>(pub T);

// Data returned to the client application
pub struct ClientApplicationData<T> {
    pub data: Option<T>,
}
pub trait ApplicationCallback {
    // Should contain eg ClientApplicationData
    fn on_result(data: ());
}

// Protocol should have its own error type but for now we alias
type ProtocolError = anyhow::Error;
