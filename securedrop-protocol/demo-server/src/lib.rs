//! Demo SecureDrop protocol server.
//!
//! This is not a production server! All state is held in memory.

mod session;

pub use session::Server;
