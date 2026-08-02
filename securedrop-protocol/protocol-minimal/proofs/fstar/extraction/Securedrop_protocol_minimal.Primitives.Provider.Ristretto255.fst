module Securedrop_protocol_minimal.Primitives.Provider.Ristretto255
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A canonically encoded scalar in $\mathbb{Z}_\ell$.
let v_SK_LEN: usize = mk_usize 32

/// A compressed group element.
let v_PK_LEN: usize = mk_usize 32

/// Uniform bytes needed to sample a scalar.
/// We follow [RFC 9496] section 4.4 which describes wide
/// input reduced modulo the group order $\ell$.
let v_SEED_LEN: usize = mk_usize 64

/// An decompressed element of the ristretto255 group.
/// # Security
/// A `Point` can only be obtained by decoding, by the
/// element derivation function, or by a group operation on other `Point`s,
/// as described in [RFC 9496] section 6. The decompressed representation is
/// held across operations so that no operation is unnecessarily decoding
/// or encoding.
assume
val t_Point': eqtype

unfold
let t_Point = t_Point'

let impl: Core_models.Clone.t_Clone t_Point =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Marker.t_Copy t_Point

unfold
let impl_1 = impl_1'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Fmt.t_Debug t_Point

unfold
let impl_2 = impl_2'

/// A scalar in $\\mathbb{Z}_\\ell$.
assume
val t_Scalar': eqtype

unfold
let t_Scalar = t_Scalar'

let impl_3: Core_models.Clone.t_Clone t_Scalar =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Marker.t_Copy t_Scalar

unfold
let impl_4 = impl_4'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_Scalar

unfold
let impl_5 = impl_5'

/// Sample $x \\in \\mathbb{F}_\\ell$ by reducing `seed` modulo $\\ell$.
/// # Security
/// The seed should be uniformly distributed, e.g. the output of a
/// domain-separated hash function. See [RFC 9496] section 4.4.
assume
val scalar_from_wide': seed: t_Array u8 (mk_usize 64) -> t_Scalar

unfold
let scalar_from_wide = scalar_from_wide'

/// Validate `bytes` as a canonical scalar in $\\mathbb{Z}_\\ell$.
/// Returns `None` if `bytes` is not a canonical scalar.
assume
val scalar_decode': bytes: t_Array u8 (mk_usize 32) -> Core_models.Option.t_Option t_Scalar

unfold
let scalar_decode = scalar_decode'

/// The canonical encoding of `scalar`.
assume
val scalar_encode': scalar: t_Scalar -> t_Array u8 (mk_usize 32)

unfold
let scalar_encode = scalar_encode'

/// Map `seed` to a group element.
/// This is hash to group as specified in RFC 9496 section 4.3.4.
assume
val from_uniform_bytes': seed: t_Array u8 (mk_usize 64) -> t_Point

unfold
let from_uniform_bytes = from_uniform_bytes'

/// Decode `bytes` as a ristretto255 group element by performing point decompression
/// as specified in RFC 9496 section 4.3.1.
/// Returns `None` if `bytes` is not a canonical encoding of a group element.
assume
val decode': bytes: t_Array u8 (mk_usize 32) -> Core_models.Option.t_Option t_Point

unfold
let decode = decode'

/// The canonical encoding of `point`, per RFC 9496 section 4.3.2.
assume
val encode': point: t_Point -> t_Array u8 (mk_usize 32)

unfold
let encode = encode'

/// The identity element, whose canonical encoding is 32 zero bytes.
assume
val identity': Prims.unit -> t_Point

unfold
let identity = identity'

/// Compute $pk = [sk] B$, where $B$ is the ristretto255 basepoint.
assume
val secret_to_public': secret_key: t_Scalar -> t_Point

unfold
let secret_to_public = secret_to_public'

/// Diffie–Hellman agreement: compute $[scalar]\\,P$.
assume
val dh': public_key: t_Point -> scalar: t_Scalar -> t_Point

unfold
let dh = dh'
