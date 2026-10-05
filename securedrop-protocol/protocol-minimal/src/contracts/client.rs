pub(crate) struct NetworkError;
pub(crate) struct ApplicationError;

// Main functions common to all (source+journalist) clients go here.
// "Public APIs" (that represent user events/interactions) go here.
// These are function headers only, a "contract" for downstream crates to implement to interact with the protocol.
// Our integration testing (setup.rs and core.rs) would operate on these APIs instead of reaching into
// the crates to set up individual components, keys, etc.
trait ClientApplication {

    type Api: ClientApi;
    type Protocol: ClientProtocol;

    // Basic format
    pub fn example() -> Result<(), ApplicationError>;

    // High-level application methods to go here
    todo!("unimplemented");

}

/// Main network calls common to all (source+journalist) clients go here.
/// This can have a default impl.
/// No logic, no rng awareness, network handling only
trait ClientApi {

    /// Basic format
    pub fn example() -> Result<(), NetworkError>;

    /// Get a Welcome Bundle from the server.
    /// This is the first information fetched by the client,
    /// and occurs on visiting the home page of an instance.
    todo!("unimplemented");

    /// Get Short-Lived Keys for all available journalists
    todo!("unimplemented");
    
    /// Get Message Challenges
    todo!("unimplemented");
    
    /// Get Single Message by ID
    todo!("unimplemented");
   
}

/// Additional API operations available to journalists via the Journalist Application.
/// Note: since API is unauthenticated, this endpoint is not protected.
/// Servers must reject enrollment bundles with signatures that
/// do not belong to enrolled journalists.
trait JournalistApi: ClientApi {
    /// Upload an Enrollment Bundle
    todo!("unimplemented");

    /// Upload pool of short-lived Keybundles
    todo!("unimplemented");

}