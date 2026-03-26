use alloc::vec::Vec;
use core::marker::PhantomData;

use anyhow::Error;
use libcrux_ed25519::{SigningKey as LibCruxSigningKey, VerificationKey as LibCruxVerifyingKey};
use rand_core::CryptoRng;

// Sealing module: prevents external crates from implementing `DomainTag`.
mod private {
    pub trait Sealed {}
}

/// Marker trait for signature domain separation.
///
/// Each impl encodes the ASCII tag that is prepended to every signing preimage
/// in that domain: `len(tag) || tag || msg`  (see footnote in the spec).
pub trait DomainTag: private::Sealed {
    #[doc(hidden)]
    const TAG: &'static [u8];
}

/// Journalist self-signature over long-term public keys (step 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalistLongTermKey;

/// Journalist self-signature over ephemeral key bundles (step 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalistEphemeralKey;

/// Newsroom signature over a journalist's verifying key (steps 3.1, 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsroomOnJournalist;

/// FPF signature over the newsroom's verifying key (step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpfOnNewsroom;

impl private::Sealed for JournalistLongTermKey {}
impl private::Sealed for JournalistEphemeralKey {}
impl private::Sealed for NewsroomOnJournalist {}
impl private::Sealed for FpfOnNewsroom {}

impl DomainTag for JournalistLongTermKey {
    const TAG: &'static [u8] = b"j-sig-ltk";
}
impl DomainTag for JournalistEphemeralKey {
    const TAG: &'static [u8] = b"j-sig-eph";
}
impl DomainTag for NewsroomOnJournalist {
    const TAG: &'static [u8] = b"nr-sig";
}
impl DomainTag for FpfOnNewsroom {
    const TAG: &'static [u8] = b"fpf-sig-nr";
}

/// An Ed25519 signature carrying its domain at the type level.
///
/// A `Signature<D>` can only be verified against a message using the same
/// domain `D`, making cross-domain misuse a compile error rather than a
/// runtime failure.
pub struct Signature<D: DomainTag> {
    bytes: [u8; 64],
    _phantom: PhantomData<fn() -> D>,
}

impl<D: DomainTag> Copy for Signature<D> {}
impl<D: DomainTag> Clone for Signature<D> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<D: DomainTag> core::fmt::Debug for Signature<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Signature").field(&self.bytes).finish()
    }
}
impl<D: DomainTag> PartialEq for Signature<D> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl<D: DomainTag> Eq for Signature<D> {}

impl<D: DomainTag> Signature<D> {
    pub(crate) fn from_bytes(bytes: [u8; 64]) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }
}

/// Construct the tagged signing preimage: `len(tag) || tag || msg`.
fn tagged_preimage<D: DomainTag>(msg: &[u8]) -> Vec<u8> {
    let tag = D::TAG;
    let mut preimage = Vec::with_capacity(1 + tag.len() + msg.len());
    preimage.push(tag.len() as u8);
    preimage.extend_from_slice(tag);
    preimage.extend_from_slice(msg);
    preimage
}

/// An Ed25519 signing key.
pub struct SigningKey {
    pub vk: VerifyingKey,
    sk: LibCruxSigningKey,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("vk", &self.vk)
            .finish_non_exhaustive()
    }
}

/// An Ed25519 verification key.
#[derive(Copy, Clone)]
pub struct VerifyingKey(LibCruxVerifyingKey);

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(&self.into_bytes())
            .finish()
    }
}

impl SigningKey {
    /// Generate a signing key from the supplied `rng`.
    pub fn new(mut rng: &mut impl CryptoRng) -> Result<SigningKey, Error> {
        let (sk, vk) = libcrux_ed25519::generate_key_pair(&mut rng)
            .map_err(|_| anyhow::anyhow!("Key generation failed"))?;
        Ok(SigningKey {
            vk: VerifyingKey(vk),
            sk,
        })
    }

    /// Sign `msg` in domain `D`, returning a `Signature<D>`.
    ///
    /// The actual preimage is `len(tag) || tag || msg` where `tag = D::TAG`.
    pub fn sign<D: DomainTag>(&self, msg: &[u8]) -> Signature<D> {
        let preimage = tagged_preimage::<D>(msg);
        let bytes = libcrux_ed25519::sign(&preimage, self.sk.as_ref())
            .expect("Signing should not fail with valid key");
        Signature::from_bytes(bytes)
    }
}

impl VerifyingKey {
    /// Get the raw bytes of this verification key.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    /// Verify `sig` over `msg`. The domain is determined by the type of `sig`.
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify<D: DomainTag>(&self, msg: &[u8], sig: &Signature<D>) -> Result<(), Error> {
        let preimage = tagged_preimage::<D>(msg);
        libcrux_ed25519::verify(&preimage, self.0.as_ref(), &sig.bytes)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn get_rng() -> ChaCha20Rng {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS random source failed");
        ChaCha20Rng::from_seed(seed)
    }

    proptest! {
        #[test]
        fn test_sign_verify_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = get_rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let sig: Signature<JournalistLongTermKey> = signing_key.sign(&msg);
            assert!(signing_key.vk.verify(&msg, &sig).is_ok());
        }
    }

    proptest! {
        #[test]
        fn test_verify_fails_with_wrong_message(
            msg1 in proptest::collection::vec(any::<u8>(), 0..100),
            msg2 in proptest::collection::vec(any::<u8>(), 0..100)
        ) {
            if msg1 == msg2 {
                return Ok(());
            }
            let mut rng = get_rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let sig: Signature<JournalistLongTermKey> = signing_key.sign(&msg1);
            assert!(signing_key.vk.verify(&msg2, &sig).is_err());
        }
    }

    proptest! {
        #[test]
        fn test_verify_fails_with_wrong_key(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = get_rng();
            let key1 = SigningKey::new(&mut rng).unwrap();
            let key2 = SigningKey::new(&mut rng).unwrap();
            let sig: Signature<JournalistLongTermKey> = key1.sign(&msg);
            assert!(key2.vk.verify(&msg, &sig).is_err());
        }
    }

    proptest! {
        #[test]
        fn test_domain_separation(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = get_rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let sig: Signature<JournalistLongTermKey> = signing_key.sign(&msg);
            let cross_domain_sig: Signature<JournalistEphemeralKey> =
                Signature::from_bytes(sig.bytes);
            assert!(signing_key.vk.verify(&msg, &cross_domain_sig).is_err());
        }
    }
}
