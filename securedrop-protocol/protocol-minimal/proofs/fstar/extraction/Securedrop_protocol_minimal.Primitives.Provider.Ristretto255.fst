module Securedrop_protocol_minimal.Primitives.Provider.Ristretto255
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A canonically encoded scalar in $\mathbb{Z}_\ell$.
let v_SK_LEN: usize = mk_usize 32

/// A compressed group element.
let v_PK_LEN: usize = mk_usize 32

/// A DH output is also a compressed group element.
let v_LEN_DH_SHARE: usize = mk_usize 32

/// Uniform bytes needed to sample a scalar.
/// We follow [RFC 9496] section 4.4 which describes wide
/// input reduced modulo the group order $\ell$.
let v_SEED_LEN: usize = mk_usize 64

/// Sample $x \\in \\mathbb{F}_\\ell$ by reducing `seed` modulo $\\ell$.
/// # Security
/// The seed should be uniformly distributed, e.g. the output of a
/// domain-separated hash function. See [RFC 9496] section 4.4.
assume
val scalar_from_wide': seed: t_Array u8 (mk_usize 64) -> t_Array u8 (mk_usize 32)

unfold
let scalar_from_wide = scalar_from_wide'

/// Compute $pk = [sk] B$, where $B$ is the ristretto255 basepoint.
/// Returns `None` if `secret_key` is not a canonical scalar.
assume
val secret_to_public': secret_key: t_Array u8 (mk_usize 32)
  -> Core_models.Option.t_Option (t_Array u8 (mk_usize 32))

unfold
let secret_to_public = secret_to_public'

/// Map `seed` to a group element.
/// This is hash to group as specified in RFC 9496 section 4.3.4.
assume
val from_uniform_bytes': seed: t_Array u8 (mk_usize 64) -> t_Array u8 (mk_usize 32)

unfold
let from_uniform_bytes = from_uniform_bytes'

/// Decode `bytes` as a ristretto255 group element by performing point decompression
/// as specified in RFC 9496 section 4.3.1.
/// Returns the element\'s canonical encoding, or `None` if `bytes` is not a
/// valid, canonical encoding of a group element.
assume
val decode': bytes: t_Array u8 (mk_usize 32)
  -> Core_models.Option.t_Option (t_Array u8 (mk_usize 32))

unfold
let decode = decode'

/// Validate `bytes` as a canonical scalar in $\\mathbb{Z}_\\ell$.
/// Returns the canonical encoding, or `None` if `bytes` is not a canonical
/// scalar.
assume
val scalar_decode': bytes: t_Array u8 (mk_usize 32)
  -> Core_models.Option.t_Option (t_Array u8 (mk_usize 32))

unfold
let scalar_decode = scalar_decode'

/// Diffie–Hellman agreement: decompress `public_key` and compute
/// $[scalar]\\,P$, returning the compressed result.
/// Returns `None` if `public_key` is not a valid group element encoding or
/// `scalar` is not canonical.
/// TODO(Jen): We are performing point decompression twice due to this bytes interface
assume
val dh': public_key: t_Array u8 (mk_usize 32) -> scalar: t_Array u8 (mk_usize 32)
  -> Core_models.Option.t_Option (t_Array u8 (mk_usize 32))

unfold
let dh = dh'
