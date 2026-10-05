pub(crate) struct ServerApplicationError;
pub(crate) struct ServerApiError;

/// Server application methods go here.
/// This ties the components of the server code together.
/// Public APIs are implemented here, and can call on different components.
/// This trait is publicly exported, and a separate application crate implements it.
trait ServerApplication {

    type ServerApi: ServerApi;
    type Protocol: ServerProtocol;
    

}

/// Server APIs, corresponding to Client methods.
/// This trait is publicly exported, and a separate application crate implements it.
trait ServerApi {
    // Receive (but don't process, that is a protocol operation) FPF-signed newsroom key
    // Receive unsigned newsroom key (autonomous enrollment, see [Server, api] Autonomous vs fpf-signed enrollment should return different response types #412)
    // Receive signed journalist enrolment bundle
    // Receive (journalist self-signed) short-lived keybundles
    // Receive an encrypted payload and store it with a randomly-generated uuid
    // Serve a collection of already-generated fetch challenges (fetch challenge generation part of protocol contract, see below)
    // Serve a welcome bundle
    // Serve journalist short-lived key bundle

}