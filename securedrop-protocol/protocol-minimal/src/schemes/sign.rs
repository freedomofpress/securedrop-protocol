use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use anyhow::Error;
use rand_core::CryptoRng;
use serde::de::Error as _;

use crate::primitives::provider;

const KEY_LEN_ED25519: usize = 32;

const SIG_LEN_ED25519: usize = 64;

/// Longest allowed domain tag for signing (255).
const MAX_TAG_LEN: usize = u8::MAX as usize;

/// The one byte length prefix plus the longest possible domain tag.
pub(crate) const MAX_PREIMAGE_OVERHEAD: usize = 1 + MAX_TAG_LEN;

// Sealing module: prevents external crates from implementing `DomainTag`.
#[cfg(not(hax))]
mod private {
    pub trait Sealed {}
}

/// Marker trait for signature domain separation.
///
/// Each impl encodes the ASCII tag that is prepended to every signing preimage
/// in that domain: `len(tag) || tag || msg`  (see footnote in the spec).
#[cfg(not(hax))]
pub trait DomainTag: private::Sealed {
    #[doc(hidden)]
    fn tag() -> &'static [u8];
}
#[cfg(hax)]
#[hax_lib::attributes]
pub trait DomainTag {
    #[doc(hidden)]
    // Currently we need to duplicate these checks in the impls
    // See: https://github.com/pereq-dev/hax/issues/789
    //
    // We also have to specify there's no precondition explicitly (that's what the trivial
    // `requires(true)` is doing) for this to verify the generic calls, otherwise hax extracts
    // an abstract precondition that cannot be proven
    #[requires(true)]
    #[ensures(|result| result.len() <= MAX_TAG_LEN)]
    fn tag() -> &'static [u8];
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

#[cfg(not(hax))]
mod sealed_impls {
    use super::*;

    impl private::Sealed for JournalistLongTermKey {}
    impl private::Sealed for JournalistEphemeralKey {}
    impl private::Sealed for NewsroomOnJournalist {}
    impl private::Sealed for FpfOnNewsroom {}
}

#[cfg_attr(hax, hax_lib::attributes)]
impl DomainTag for JournalistLongTermKey {
    #[cfg_attr(hax, ensures(|result| result.len() <= MAX_TAG_LEN))]
    fn tag() -> &'static [u8] {
        b"j-sig-ltk"
    }
}
#[cfg_attr(hax, hax_lib::attributes)]
impl DomainTag for JournalistEphemeralKey {
    #[cfg_attr(hax, ensures(|result| result.len() <= MAX_TAG_LEN))]
    fn tag() -> &'static [u8] {
        b"j-sig-eph"
    }
}
#[cfg_attr(hax, hax_lib::attributes)]
impl DomainTag for NewsroomOnJournalist {
    #[cfg_attr(hax, ensures(|result| result.len() <= MAX_TAG_LEN))]
    fn tag() -> &'static [u8] {
        b"nr-sig"
    }
}
#[cfg_attr(hax, hax_lib::attributes)]
impl DomainTag for FpfOnNewsroom {
    #[cfg_attr(hax, ensures(|result| result.len() <= MAX_TAG_LEN))]
    fn tag() -> &'static [u8] {
        b"fpf-sig-nr"
    }
}

/// An Ed25519 signature carrying its domain at the type level.
///
/// A `Signature<D>` can only be verified against a message using the same
/// domain `D`, making cross-domain misuse a compile error rather than a
/// runtime failure.
pub struct Signature<D: DomainTag> {
    bytes: [u8; SIG_LEN_ED25519],
    // `PhantomData<D>` rather than `PhantomData<fn() -> D>`: the function type
    // has no decidable equality in F*, which blocks `t_Signature` extraction.
    _phantom: PhantomData<D>,
}

impl<D: DomainTag> Copy for Signature<D> {}
impl<D: DomainTag> Clone for Signature<D> {
    fn clone(&self) -> Self {
        *self
    }
}

// hax struggles with the debug format function signature, but it is
// debug only, so we can exclude it from extraction
#[cfg_attr(hax, hax_lib::exclude)]
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
// `Signature<D>` carries `PhantomData<fn() -> D>`, a function type with no
// decidable equality in F*; the `Eq` marker would force `t_Signature` to be an
// eqtype and fail extraction. We only need value equality (`PartialEq`, above).
#[cfg(not(hax))]
impl<D: DomainTag> Eq for Signature<D> {}

impl<D: DomainTag> Signature<D> {
    pub const LEN: usize = SIG_LEN_ED25519;

    /// Reconstruct a [`Signature`] from its serialization.
    pub fn from_bytes(bytes: [u8; SIG_LEN_ED25519]) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }

    /// The byte serialization of this signature.
    pub fn as_bytes(&self) -> [u8; SIG_LEN_ED25519] {
        self.bytes
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl<D: DomainTag> serde::Serialize for Signature<D> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.bytes))
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl<'de, D: DomainTag> serde::Deserialize<'de> for Signature<D> {
    fn deserialize<De: serde::Deserializer<'de>>(de: De) -> Result<Self, De::Error> {
        let s = String::deserialize(de)?;
        let mut bytes = [0u8; SIG_LEN_ED25519];
        hex::decode_to_slice(s.trim(), &mut bytes).map_err(De::Error::custom)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Construct the tagged signing preimage: `len(tag) || tag || msg`.
#[cfg_attr(hax, hax_lib::requires(msg.len() <= usize::MAX - MAX_PREIMAGE_OVERHEAD))]
fn tagged_preimage<D: DomainTag>(msg: &[u8]) -> Vec<u8> {
    let tag = D::tag();
    #[cfg(not(hax))]
    {
        debug_assert!(tag.len() <= MAX_TAG_LEN, "tag length exceeds u8::MAX");
        debug_assert!(tag.is_ascii(), "tag contains non-ASCII bytes");
    }
    let mut preimage = Vec::with_capacity(1 + tag.len() + msg.len());
    preimage.push(tag.len() as u8);
    preimage.extend_from_slice(tag);
    preimage.extend_from_slice(msg);
    preimage
}

/// An Ed25519 verification key.
#[derive(Copy, Clone)]
pub struct VerifyingKey([u8; KEY_LEN_ED25519]);

/// An Ed25519 signing key.
pub(crate) struct SigningSecretKey([u8; KEY_LEN_ED25519]);

impl VerifyingKey {
    pub const LEN: usize = KEY_LEN_ED25519;

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN_ED25519] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN_ED25519]) -> Self {
        Self(bytes)
    }
}

impl SigningSecretKey {
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN_ED25519] {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN_ED25519]) -> Self {
        Self(bytes)
    }
}

pub struct SigningKey {
    pub vk: VerifyingKey,
    sk: SigningSecretKey,
}

// hax struggles with the debug format function signature, but it is
// debug only, so we can exclude it from extraction
#[cfg_attr(hax, hax_lib::exclude)]
impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("vk", &self.vk)
            .finish_non_exhaustive()
    }
}

// hax struggles with the debug format function signature, but it is
// debug only, so we can exclude it from extraction
#[cfg_attr(hax, hax_lib::exclude)]
impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifyingKey")
            .field(&self.into_bytes())
            .finish()
    }
}

#[cfg_attr(hax, hax_lib::attributes)]
impl SigningKey {
    pub const SEED_LEN: usize = KEY_LEN_ED25519;

    /// Generate a signing key from the supplied `rng`.
    pub fn new<R: CryptoRng>(rng: &mut R) -> Result<SigningKey, Error> {
        let (sk, vk) = provider::ed25519::keygen(rng)?;
        Ok(SigningKey {
            vk: VerifyingKey(vk),
            sk: SigningSecretKey(sk),
        })
    }

    /// Sign `msg` in domain `D`, returning a `Signature<D>`.
    ///
    /// The actual preimage is `len(tag) || tag || msg` where `tag = D::TAG`.
    #[cfg_attr(hax, requires(msg.len() <= usize::MAX - MAX_PREIMAGE_OVERHEAD))]
    pub fn sign<D: DomainTag>(&self, msg: &[u8]) -> Signature<D> {
        let preimage = tagged_preimage::<D>(msg);
        let bytes = provider::ed25519::sign(&preimage, self.sk.as_bytes());
        Signature::from_bytes(bytes)
    }

    pub(crate) fn as_bytes(&self) -> [u8; Self::SEED_LEN] {
        *self.sk.as_bytes()
    }

    pub(crate) fn from_seed(seed: [u8; Self::SEED_LEN]) -> Self {
        let mut pk = [0u8; KEY_LEN_ED25519];
        provider::ed25519::secret_to_public(&mut pk, &seed);
        Self {
            vk: VerifyingKey(pk),
            sk: SigningSecretKey(seed),
        }
    }
}

#[cfg_attr(hax, hax_lib::attributes)]
impl VerifyingKey {
    /// Get the raw bytes of this verification key.
    pub fn into_bytes(self) -> [u8; KEY_LEN_ED25519] {
        self.0
    }

    /// Verify `sig` over `msg`. The domain is determined by the type of `sig`.
    ///
    /// Returns an error if the signature is invalid.
    #[cfg_attr(hax, requires(msg.len() <= usize::MAX - MAX_PREIMAGE_OVERHEAD))]
    pub fn verify<D: DomainTag>(&self, msg: &[u8], sig: &Signature<D>) -> Result<(), Error> {
        let preimage = tagged_preimage::<D>(msg);
        provider::ed25519::verify(&preimage, self.as_bytes(), &sig.bytes)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl serde::Serialize for VerifyingKey {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(self.0.as_ref()))
    }
}

#[cfg_attr(hax, hax_lib::exclude)]
impl<'de> serde::Deserialize<'de> for VerifyingKey {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let mut bytes = [0u8; KEY_LEN_ED25519];
        hex::decode_to_slice(s.trim(), &mut bytes).map_err(D::Error::custom)?;
        Ok(Self::from_bytes(bytes))
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
        fn test_signature_byte_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = get_rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let sig: Signature<JournalistLongTermKey> = signing_key.sign(&msg);
            let sig2 = Signature::<JournalistLongTermKey>::from_bytes(sig.as_bytes());
            prop_assert!(signing_key.vk.verify(&msg, &sig2).is_ok());
        }
    }

    proptest! {
        #[test]
        fn test_verifying_key_byte_roundtrip(msg in proptest::collection::vec(any::<u8>(), 0..100)) {
            let mut rng = get_rng();
            let signing_key = SigningKey::new(&mut rng).unwrap();
            let sig: Signature<JournalistLongTermKey> = signing_key.sign(&msg);
            let vk = VerifyingKey::from_bytes(signing_key.vk.into_bytes());
            prop_assert!(vk.verify(&msg, &sig).is_ok());
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
