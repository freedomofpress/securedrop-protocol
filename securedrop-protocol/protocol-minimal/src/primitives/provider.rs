/// Import required crypto provider params.
/// Allows other modules to use crypto provider opaquely
///
pub mod curve25519 {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const SK_LEN: usize = libcrux_curve25519::DK_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const PK_LEN: usize = libcrux_curve25519::EK_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_DH_SHARE: usize = libcrux_curve25519::SS_LEN;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_curve25519::secret_to_public;
}

/// ristretto255 [RFC 9496] backed by `curve25519-dalek`.
pub mod ristretto255 {

    #[cfg_attr(hax, hax_lib::opaque)]
    use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};

    /// A canonically encoded scalar in $\mathbb{Z}_\ell$.
    pub(crate) const SK_LEN: usize = 32;

    /// A compressed group element.
    pub(crate) const PK_LEN: usize = 32;

    /// A DH output is also a compressed group element.
    pub(crate) const LEN_DH_SHARE: usize = 32;

    /// Uniform bytes needed to sample a scalar.
    ///
    /// We follow [RFC 9496] section 4.4 which describes wide
    /// input reduced modulo the group order $\ell$.
    pub(crate) const SEED_LEN: usize = 64;

    /// Sample $x \in \mathbb{F}_\ell$ by reducing `seed` modulo $\ell$.
    ///
    /// # Security
    ///
    /// The seed should be uniformly distributed, e.g. the output of a
    /// domain-separated hash function. See [RFC 9496] section 4.4.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn scalar_from_wide(seed: &[u8; SEED_LEN]) -> [u8; SK_LEN] {
        Scalar::from_bytes_mod_order_wide(seed).to_bytes()
    }

    /// Compute $pk = [sk] B$, where $B$ is the ristretto255 basepoint.
    ///
    /// Returns `None` if `secret_key` is not a canonical scalar.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn secret_to_public(secret_key: &[u8; SK_LEN]) -> Option<[u8; PK_LEN]> {
        let sk: Option<Scalar> = Scalar::from_canonical_bytes(*secret_key).into();
        Some(RistrettoPoint::mul_base(&sk?).compress().to_bytes())
    }

    /// Map `seed` to a group element.
    ///
    /// This is hash to group as specified in RFC 9496 section 4.3.4.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn from_uniform_bytes(seed: &[u8; SEED_LEN]) -> [u8; PK_LEN] {
        RistrettoPoint::from_uniform_bytes(seed)
            .compress()
            .to_bytes()
    }

    /// Decode `bytes` as a ristretto255 group element by performing point decompression
    /// as specified in RFC 9496 section 4.3.1.
    ///
    /// Returns the element's canonical encoding, or `None` if `bytes` is not a
    /// valid, canonical encoding of a group element.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn decode(bytes: &[u8; PK_LEN]) -> Option<[u8; PK_LEN]> {
        let point = CompressedRistretto::from_slice(bytes).ok()?.decompress()?;
        Some(point.compress().to_bytes())
    }

    /// Validate `bytes` as a canonical scalar in $\mathbb{Z}_\ell$.
    ///
    /// Returns the canonical encoding, or `None` if `bytes` is not a canonical
    /// scalar.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn scalar_decode(bytes: &[u8; SK_LEN]) -> Option<[u8; SK_LEN]> {
        let scalar: Option<Scalar> = Scalar::from_canonical_bytes(*bytes).into();
        Some(scalar?.to_bytes())
    }

    /// Diffie–Hellman agreement: decompress `public_key` and compute
    /// $[scalar]\,P$, returning the compressed result.
    ///
    /// Returns `None` if `public_key` is not a valid group element encoding or
    /// `scalar` is not canonical.
    ///
    /// TODO(Jen): We are performing point decompression twice due to this bytes interface
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn dh(
        public_key: &[u8; PK_LEN],
        scalar: &[u8; SK_LEN],
    ) -> Option<[u8; LEN_DH_SHARE]> {
        let point = CompressedRistretto::from_slice(public_key)
            .ok()?
            .decompress()?;
        let sk: Option<Scalar> = Scalar::from_canonical_bytes(*scalar).into();
        Some((point * sk?).compress().to_bytes())
    }
}

pub mod ed25519 {
    use rand_core::CryptoRng;

    /// Generate an ed25519 keypair
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn keygen<R: CryptoRng>(rng: &mut R) -> Result<([u8; 32], [u8; 32]), anyhow::Error> {
        let (sk, vk) = libcrux_ed25519::generate_key_pair(rng)
            .map_err(|_| anyhow::anyhow!("Key generation failed"))?;
        Ok((sk.into_bytes(), vk.into_bytes()))
    }

    /// Sign `payload` with Ed25519 secret key bytes.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn sign(payload: &[u8], private_key: &[u8; 32]) -> [u8; 64] {
        libcrux_ed25519::sign(payload, private_key).expect("Ed25519 signing is infallible")
    }

    /// Verify an Ed25519 `signature` over `payload` with verifying key bytes.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn verify(
        payload: &[u8],
        public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), anyhow::Error> {
        libcrux_ed25519::verify(payload, public_key, signature)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }

    /// Derive the Ed25519 public key from a secret key.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn secret_to_public(public_key: &mut [u8; 32], secret_key: &[u8; 32]) {
        libcrux_ed25519::secret_to_public(public_key, secret_key)
    }
}

pub mod rng {
    use rand_core::{CryptoRng, RngCore};

    /// Fill `dest` with random bytes from `rng`
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn fill_bytes<R: RngCore + CryptoRng, const N: usize>(
        rng: &mut R,
        dest: &mut [u8; N],
    ) {
        rng.fill_bytes(dest);
    }
}

pub mod uuid_parse {

    /// Parse a `Uuid` from bytes
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn from_slice(bytes: &[u8]) -> ::uuid::Uuid {
        ::uuid::Uuid::from_slice(bytes).expect("message id must be 16 bytes")
    }
}

pub mod kem {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_kem::{
        Algorithm, MlKem768, PrivateKey, PublicKey, key_gen, key_gen_derand,
    };
}

pub mod traits {

    // todo deprecate
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_traits::kem::owned::Kem as OwnedKem;
}

pub mod mlkem {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const KEY_GENERATION_SEED_SIZE: usize = libcrux_ml_kem::KEY_GENERATION_SEED_SIZE;

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_ml_kem::mlkem768;
}

pub mod chacha20poly1305 {

    #[cfg_attr(hax, hax_lib::opaque)]
    use libcrux_chacha20poly1305::AeadError;

    pub(crate) const KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;

    pub(crate) const NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;

    pub(crate) const TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;

    // #[cfg_attr(hax, hax_lib::opaque)]
    // pub(crate) use libcrux_chacha20poly1305::{decrypt, encrypt};

    #[cfg_attr(hax, hax_lib::ensures(|_result| future(ciphertext).len() == ciphertext.len()))]
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn encrypt(
        key: &[u8; KEY_LEN],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        aad: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), AeadError> {
        libcrux_chacha20poly1305::encrypt(key, plaintext, ciphertext, aad, nonce).map(|_| ())
    }

    // Hax extraction is struggling with the types
    #[cfg_attr(hax, hax_lib::opaque)]
    pub fn decrypt(
        key: &[u8; KEY_LEN],
        plaintext: &mut [u8],
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), AeadError> {
        libcrux_chacha20poly1305::decrypt(key, plaintext, ciphertext, aad, nonce).map(|_| ())
    }
}

pub mod hkdf {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use libcrux_hkdf::ExpandError;

    #[cfg_attr(hax, hax_lib::opaque)]
    use libcrux_hkdf::Algorithm;

    /// HKDF-SHA256
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) fn sha256(
        okm: &mut [u8],
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
    ) -> Result<(), ExpandError> {
        libcrux_hkdf::hkdf(Algorithm::Sha256, okm, salt, ikm, info)
    }
}

pub mod hpke_rs {

    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) use hpke_rs::{
        Hpke, HpkePrivateKey, HpkePublicKey, Mode, hpke_types::AeadAlgorithm::ChaCha20Poly1305,
        hpke_types::KdfAlgorithm::HkdfSha256, hpke_types::KemAlgorithm::DhKem25519,
        hpke_types::KemAlgorithm::XWingDraft06, libcrux::HpkeLibcrux,
    };
}

pub mod constants {

    // Message ID (uuid) and KMID
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_MESSAGE_ID: usize = 16;
    // TODO: current implementation prepends the nonce to the encrypted message.
    // Recheck this when switching implementations.
    #[cfg_attr(hax, hax_lib::opaque)]
    pub(crate) const LEN_KMID: usize = crate::primitives::provider::chacha20poly1305::TAG_LEN
        + crate::primitives::provider::chacha20poly1305::NONCE_LEN
        + LEN_MESSAGE_ID;
}
