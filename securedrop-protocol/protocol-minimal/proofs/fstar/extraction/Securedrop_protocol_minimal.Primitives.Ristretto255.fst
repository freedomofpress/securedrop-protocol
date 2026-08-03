module Securedrop_protocol_minimal.Primitives.Ristretto255
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  ()

let v_DH_PUBLIC_KEY_LEN: usize =
  Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.v_PK_LEN

let v_DH_PRIVATE_KEY_LEN: usize =
  Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.v_SK_LEN

/// Uniform bytes required to derive a scalar per [RFC 9496] section 4.4.
let v_DH_SEED_LEN: usize = Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.v_SEED_LEN

/// A ristretto255 group element.
/// # Security
/// This can be instantiated only by decoding, by the element derivation
/// function, or by a group operation, so it is always a valid ristretto255
/// element. The element is held decompressed, so repeated operations on the
/// same key do not repeat point decompression.
type t_DHPublicKey =
  | DHPublicKey : Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Point
    -> t_DHPublicKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Fmt.t_Debug t_DHPublicKey

unfold
let impl_2 = impl_2'

let impl_3: Core_models.Clone.t_Clone t_DHPublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Marker.t_Copy t_DHPublicKey

unfold
let impl_4 = impl_4'

/// A ristretto255 scalar in $\mathbb{Z}_\ell$.
/// This can be instantiated only by validating decode or by wide reduction, so
/// it is always canonical.
type t_DHPrivateKey =
  | DHPrivateKey : Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Scalar
    -> t_DHPrivateKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_DHPrivateKey

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_DHPrivateKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Decode a group element from its 32 byte encoding, validating that it is a
/// real ristretto255 element.
/// This must be used for any untrusted bytes (wire or storage) such that an
/// invalid element cannot be instantiated.
let impl_DHPublicKey__decode (bytes: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result t_DHPublicKey Anyhow.t_Error =
  Core_models.Option.impl__ok_or_else #t_DHPublicKey
    #Anyhow.t_Error
    #(Prims.unit -> Anyhow.t_Error)
    (Core_models.Option.impl__map #Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Point
        #t_DHPublicKey
        #(Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Point -> t_DHPublicKey)
        (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.decode bytes
          <:
          Core_models.Option.t_Option
          Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Point)
        DHPublicKey
      <:
      Core_models.Option.t_Option t_DHPublicKey)
    (fun temp_0_ ->
        let _:Prims.unit = temp_0_ in
        let error:Anyhow.t_Error =
          Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                (let list = ["invalid ristretto255 point encoding"] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list)
              <:
              Core_models.Fmt.t_Arguments)
        in
        Anyhow.__private.must_use error)

/// The canonical 32-byte encoding of this element.
let impl_DHPublicKey__into_bytes (self: t_DHPublicKey) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.encode self._0

/// Decode a scalar from bytes, validating it is a canonical element of
/// $\mathbb{Z}_\ell$.
let impl_DHPrivateKey__decode (bytes: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result t_DHPrivateKey Anyhow.t_Error =
  Core_models.Option.impl__ok_or_else #t_DHPrivateKey
    #Anyhow.t_Error
    #(Prims.unit -> Anyhow.t_Error)
    (Core_models.Option.impl__map #Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Scalar
        #t_DHPrivateKey
        #(Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Scalar -> t_DHPrivateKey)
        (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_decode bytes
          <:
          Core_models.Option.t_Option
          Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.t_Scalar)
        DHPrivateKey
      <:
      Core_models.Option.t_Option t_DHPrivateKey)
    (fun temp_0_ ->
        let _:Prims.unit = temp_0_ in
        let error:Anyhow.t_Error =
          Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                (let list = ["non-canonical ristretto255 scalar"] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list)
              <:
              Core_models.Fmt.t_Arguments)
        in
        Anyhow.__private.must_use error)

/// Derive the public key $[sk] B$.
let impl_DHPrivateKey__public_key (self: t_DHPrivateKey) : t_DHPublicKey =
  DHPublicKey
  (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.secret_to_public self._0)
  <:
  t_DHPublicKey

/// The canonical encoding of this scalar.
let impl_DHPrivateKey__to_bytes (self: t_DHPrivateKey) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_encode self._0

/// Derive a DH keypair from a caller-supplied uniform seed.
/// Used for keys that must be reproducible from a key hierarchy (the source's
/// $sk_S^{fetch}$), and for deterministic tests.
let deterministic_dh_keygen (randomness: t_Array u8 (mk_usize 64))
    : (t_DHPrivateKey & t_DHPublicKey) =
  let secret_key:t_DHPrivateKey =
    DHPrivateKey
    (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_from_wide randomness)
    <:
    t_DHPrivateKey
  in
  let public_key:t_DHPublicKey = impl_DHPrivateKey__public_key secret_key in
  secret_key, public_key <: (t_DHPrivateKey & t_DHPublicKey)

/// Generate a new ristretto255 DH keypair
let generate_dh_keypair
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & (t_DHPrivateKey & t_DHPublicKey)) =
  let randomness:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 64)) =
    Securedrop_protocol_minimal.Primitives.Provider.Rng.fill_bytes #v_R (mk_usize 64) rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 64) = tmp1 in
  let _:Prims.unit = () in
  let hax_temp_output:(t_DHPrivateKey & t_DHPublicKey) = deterministic_dh_keygen randomness in
  rng, hax_temp_output <: (v_R & (t_DHPrivateKey & t_DHPublicKey))

/// The seed to [`placeholder_public_key`].
let v_PLACEHOLDER_SEED: t_Slice u8 =
  (let list =
      [
        mk_u8 115; mk_u8 101; mk_u8 99; mk_u8 117; mk_u8 114; mk_u8 101; mk_u8 100; mk_u8 114;
        mk_u8 111; mk_u8 112; mk_u8 45; mk_u8 112; mk_u8 114; mk_u8 111; mk_u8 116; mk_u8 111;
        mk_u8 99; mk_u8 111; mk_u8 108; mk_u8 45; mk_u8 112; mk_u8 108; mk_u8 97; mk_u8 99;
        mk_u8 101; mk_u8 104; mk_u8 111; mk_u8 108; mk_u8 100; mk_u8 101; mk_u8 114; mk_u8 45;
        mk_u8 118; mk_u8 49
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 34);
    Rust_primitives.Hax.array_of_list 34 list)
  <:
  t_Slice u8

/// A fixed group element used as a placeholder value.
let placeholder_public_key (_: Prims.unit) : t_DHPublicKey =
  let seed:t_Array u8 (mk_usize 64) =
    Securedrop_protocol_minimal.Primitives.Provider.Sha2.sha512 v_PLACEHOLDER_SEED
  in
  DHPublicKey (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.from_uniform_bytes seed)
  <:
  t_DHPublicKey

/// Sample a uniformly random group element.
let random_dh_public_key
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & t_DHPublicKey) =
  let randomness:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 64)) =
    Securedrop_protocol_minimal.Primitives.Provider.Rng.fill_bytes #v_R (mk_usize 64) rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 64) = tmp1 in
  let _:Prims.unit = () in
  let hax_temp_output:t_DHPublicKey =
    DHPublicKey
    (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.from_uniform_bytes randomness)
    <:
    t_DHPublicKey
  in
  rng, hax_temp_output <: (v_R & t_DHPublicKey)

/// Sample a scalar $x \gets^{\$} \mathbb{F}_\ell$.
let generate_random_scalar
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & t_DHPrivateKey) =
  let randomness:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 64)) =
    Securedrop_protocol_minimal.Primitives.Provider.Rng.fill_bytes #v_R (mk_usize 64) rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 64) = tmp1 in
  let _:Prims.unit = () in
  let hax_temp_output:t_DHPrivateKey =
    DHPrivateKey
    (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_from_wide randomness)
    <:
    t_DHPrivateKey
  in
  rng, hax_temp_output <: (v_R & t_DHPrivateKey)

/// Compute DH agreement.
let dh_shared_secret (public_key: t_DHPublicKey) (scalar: t_DHPrivateKey) : t_DHPublicKey =
  DHPublicKey
  (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.dh public_key._0 scalar._0)
  <:
  t_DHPublicKey
