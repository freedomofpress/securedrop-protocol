//! Stateless server-side cryptographic operations for the setup steps of the protocol.

use crate::keys::NewsroomKeyPair;
use crate::keys::fpf::FPFKeyPair;
use crate::sign::{FpfOnNewsroom, NewsroomOnJournalist, Signature};
use crate::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistSetupRequest, JournalistSetupResponse,
    NewsroomSetupRequest, NewsroomSetupResponse,
};
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
    /// # Security
    ///
    /// There is a manual verification step here: the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the fingerprint and signature
    /// in its local data store.
    ///
    pub fn sign(self, fpf_keys: &FPFKeyPair) -> Result<NewsroomSetupResponse, Error> {
        let newsroom_pk_bytes = self.newsroom_verifying_key.into_bytes();
        let sig: Signature<FpfOnNewsroom> = fpf_keys.sign(&newsroom_pk_bytes);
        Ok(NewsroomSetupResponse { sig })
    }
}

impl JournalistSetupRequest {
    /// Setup a journalist. This corresponds to step 3.1 in the spec.
    ///
    /// The newsroom verifies the journalist's self-signature over their
    /// long-term public keys, then signs the journalist's verifying key.
    ///
    /// # Security
    ///
    /// There is a manual verification step here, so the caller should
    /// instruct the user to stop, verify the fingerprint out of band, and
    /// then proceed. The caller should also persist the enrollment and
    /// signature in its local data store.
    ///
    /// TODO(later): How to handle signing when offline?
    ///
    /// # Errors
    ///
    /// Returns an error if the journalist's self-signature does not verify.
    pub fn sign(&self, newsroom_keys: &NewsroomKeyPair) -> Result<JournalistSetupResponse, Error> {
        // Get enrollment key from the request (journalist verification key)
        let vk_j = self.enrollment.verification_key;

        // Verify journalist self-signature over their own pubkeys.
        vk_j.verify(
            &self.enrollment.bundle.bundle_bytes(),
            &self.enrollment.bundle.selfsig,
        )?;

        // Sign the journalist's verifying key.
        let sig: Signature<NewsroomOnJournalist> = newsroom_keys.sign(&vk_j.into_bytes());
        Ok(JournalistSetupResponse { sig })
    }
}

impl JournalistEphemeralKeyRequest {
    /// Handle a journalist's ephemeral key replenishment request. This
    /// corresponds to step 3.2 in the spec.
    ///
    /// Each ephemeral key bundle must be signed by the journalist's
    /// long-term signing key. The caller is responsible for checking that
    /// the journalist is enrolled, and for storing the bundles.
    ///
    /// # Errors
    ///
    /// Returns an error if any bundle signature fails verification.
    #[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
    pub fn verify(&self) -> Result<(), Error> {
        // TODO: more efficient way than verifying each signature!
        for i in 0..self.bundles.len() {
            let signed_bundle = &self.bundles[i];
            self.verifying_key
                .verify(&signed_bundle.0.as_bytes(), &signed_bundle.1)?;
        }
        Ok(())
    }
}
