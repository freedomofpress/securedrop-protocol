// Setup module for FPF hardware operations
//
// This module contains mock implementations that run on FPF hardware.

use crate::{
    FpfOnNewsroom, Signature,
    keys::fpf::FPFKeyPair,
    wire::setup::{NewsroomSetupRequest, NewsroomSetupResponse},
};

impl NewsroomSetupRequest {
    /// Setup a newsroom. This corresponds to step 2 in the spec.
    ///
    /// This runs on FPF hardware.
    ///
    /// The generated newsroom verifying key is sent to FPF,
    /// which produces a signature over the newsroom verifying key using the
    /// FPF signing key.
    ///
    /// # Security
    ///
    /// There is a manual verification step here: the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    ///
    pub fn sign(self, fpf_keys: &FPFKeyPair) -> Result<NewsroomSetupResponse, anyhow::Error> {
        let newsroom_pk_bytes = self.newsroom_verifying_key.into_bytes();
        let sig: Signature<FpfOnNewsroom> = fpf_keys.sign(&newsroom_pk_bytes);
        Ok(NewsroomSetupResponse { sig })
    }
}
