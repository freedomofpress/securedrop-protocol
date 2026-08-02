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
/// This can be instantiated only by going through point decompression
/// to ensure it is a valid ristretto255 group element.
/// TODO(jen): Internal `CompressedRistretto` and `RistrettoPoint`?
type t_DHPublicKey = | DHPublicKey : t_Array u8 (mk_usize 32) -> t_DHPublicKey

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

/// A ristretto255 scalar in $\mathbb{Z}_\ell$ canonically encoded.
/// TODO(jen): Internal `Scalar` - not doing this at this moment
/// because the providers module interface is all byte based
type t_DHPrivateKey = | DHPrivateKey : t_Array u8 (mk_usize 32) -> t_DHPrivateKey

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
  match
    Core_models.Option.impl__ok_or_else #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      #(Prims.unit -> Anyhow.t_Error)
      (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.decode bytes
        <:
        Core_models.Option.t_Option (t_Array u8 (mk_usize 32)))
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
    <:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok canonical ->
    Core_models.Result.Result_Ok (DHPublicKey canonical <: t_DHPublicKey)
    <:
    Core_models.Result.t_Result t_DHPublicKey Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_DHPublicKey Anyhow.t_Error

/// The canonical 32-byte encoding of this element.
let impl_DHPublicKey__into_bytes (self: t_DHPublicKey) : t_Array u8 (mk_usize 32) = self._0

/// Decode a scalar from bytes, validating it is a canonical element of
/// $\mathbb{Z}_\ell$.
let impl_DHPrivateKey__decode (bytes: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result t_DHPrivateKey Anyhow.t_Error =
  match
    Core_models.Option.impl__ok_or_else #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      #(Prims.unit -> Anyhow.t_Error)
      (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_decode bytes
        <:
        Core_models.Option.t_Option (t_Array u8 (mk_usize 32)))
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
    <:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok canonical ->
    Core_models.Result.Result_Ok (DHPrivateKey canonical <: t_DHPrivateKey)
    <:
    Core_models.Result.t_Result t_DHPrivateKey Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_DHPrivateKey Anyhow.t_Error

/// Derive the public key $[sk] B$.
let impl_DHPrivateKey__public_key (self: t_DHPrivateKey) : t_DHPublicKey =
  let pk:t_Array u8 (mk_usize 32) =
    Core_models.Option.impl__expect #(t_Array u8 (mk_usize 32))
      (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.secret_to_public self._0
        <:
        Core_models.Option.t_Option (t_Array u8 (mk_usize 32)))
      "DHPrivateKey holds a canonical scalar"
  in
  DHPublicKey pk <: t_DHPublicKey

let impl_DHPrivateKey__as_bytes (self: t_DHPrivateKey) : t_Array u8 (mk_usize 32) = self._0

let impl_DHPrivateKey__into_bytes (self: t_DHPrivateKey) : t_Array u8 (mk_usize 32) = self._0

/// Derive a DH keypair from a caller-supplied uniform seed.
/// Used for keys that must be reproducible from a key hierarchy (the source's
/// $sk_S^{fetch}$), and for deterministic tests.
let deterministic_dh_keygen (randomness: t_Array u8 (mk_usize 64))
    : Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error =
  let secret_key:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_from_wide randomness
  in
  match
    Core_models.Option.impl__ok_or_else #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      #(Prims.unit -> Anyhow.t_Error)
      (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.secret_to_public secret_key
        <:
        Core_models.Option.t_Option (t_Array u8 (mk_usize 32)))
      (fun temp_0_ ->
          let _:Prims.unit = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["ristretto255 key generation failed"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok public_key ->
    Core_models.Result.Result_Ok
    ((DHPrivateKey secret_key <: t_DHPrivateKey), (DHPublicKey public_key <: t_DHPublicKey)
      <:
      (t_DHPrivateKey & t_DHPublicKey))
    <:
    Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error

/// Generate a new ristretto255 DH keypair
let generate_dh_keypair
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error) =
  let randomness:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 64)) =
    Securedrop_protocol_minimal.Primitives.Provider.Rng.fill_bytes #v_R (mk_usize 64) rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 64) = tmp1 in
  let _:Prims.unit = () in
  let hax_temp_output:Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error =
    deterministic_dh_keygen randomness
  in
  rng, hax_temp_output
  <:
  (v_R & Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error)

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
    : (v_R & Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
  let randomness:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 64)) =
    Securedrop_protocol_minimal.Primitives.Provider.Rng.fill_bytes #v_R (mk_usize 64) rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 64) = tmp1 in
  let _:Prims.unit = () in
  let hax_temp_output:Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error =
    Core_models.Result.Result_Ok
    (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.scalar_from_wide randomness)
    <:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  in
  rng, hax_temp_output
  <:
  (v_R & Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)

/// Compute DH agreement.
let dh_shared_secret (public_key: t_DHPublicKey) (scalar: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result t_DHPublicKey Anyhow.t_Error =
  match
    Core_models.Option.impl__ok_or_else #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      #(Prims.unit -> Anyhow.t_Error)
      (Securedrop_protocol_minimal.Primitives.Provider.Ristretto255.dh public_key._0 scalar
        <:
        Core_models.Option.t_Option (t_Array u8 (mk_usize 32)))
      (fun temp_0_ ->
          let _:Prims.unit = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["ristretto255 DH failed"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok shared ->
    Core_models.Result.Result_Ok (DHPublicKey shared <: t_DHPublicKey)
    <:
    Core_models.Result.t_Result t_DHPublicKey Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_DHPublicKey Anyhow.t_Error
