//! Setup module for FPF hardware operations
//!
//! This module contains implementations that run on FPF hardware.

use crate::messages::setup::{NewsroomSetupRequest, NewsroomSetupResponse};
use anyhow::Error;

impl NewsroomSetupRequest {
    /// Setup a newsroom. This corresponds to step 2 in the spec.
    ///
    /// This runs on FPF hardware.
    ///
    /// The generated newsroom verifying key is sent to FPF,
    /// which produces a signature over the newsroom verifying key using the
    /// FPF signing key.
    ///
    /// TODO: There is a manual verification step here, so the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    pub fn sign() -> Result<NewsroomSetupResponse, Error> {
        unimplemented!()
    }
}
