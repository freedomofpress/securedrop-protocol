module Securedrop_protocol.Primitives.X25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_curve25519 in
  let open Libcrux_traits.Kem.Arrayref in
  let open Rand_core in
  ()

/// An X25519 public key.
type t_DHPublicKey = | DHPublicKey : t_Array u8 (mk_usize 32) -> t_DHPublicKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Fmt.t_Debug t_DHPublicKey

unfold
let impl_3 = impl_3'

let impl_4: Core_models.Clone.t_Clone t_DHPublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_DHPublicKey__into_bytes (self: t_DHPublicKey) : t_Array u8 (mk_usize 32) = self._0

let impl_DHPublicKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_DHPublicKey =
  DHPublicKey bytes <: t_DHPublicKey

/// An X25519 private key.
type t_DHPrivateKey = | DHPrivateKey : t_Array u8 (mk_usize 32) -> t_DHPrivateKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_DHPrivateKey

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_DHPrivateKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_DHPrivateKey__into_bytes (self: t_DHPrivateKey) : t_Array u8 (mk_usize 32) = self._0

let impl_DHPrivateKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_DHPrivateKey =
  DHPrivateKey bytes <: t_DHPrivateKey

/// An X25519 shared secret.
type t_DHSharedSecret = | DHSharedSecret : t_Array u8 (mk_usize 32) -> t_DHSharedSecret

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Fmt.t_Debug t_DHSharedSecret

unfold
let impl_7 = impl_7'

let impl_8: Core_models.Clone.t_Clone t_DHSharedSecret =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_DHSharedSecret__into_bytes (self: t_DHSharedSecret) : t_Array u8 (mk_usize 32) = self._0

let impl_DHSharedSecret__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_DHSharedSecret =
  DHSharedSecret bytes <: t_DHSharedSecret

/// Generate DH keypair from external randomness
/// FOR TEST PURPOSES ONLY
let deterministic_dh_keygen (randomness: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error =
  let public_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let secret_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (tmp1: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Libcrux_traits.Kem.Arrayref.t_KeyGenError) =
    Libcrux_traits.Kem.Arrayref.f_keygen #Libcrux_curve25519.t_X25519 #(mk_usize 32) #(mk_usize 32)
      #(mk_usize 32) #(mk_usize 32) #(mk_usize 32) #(mk_usize 32) #FStar.Tactics.Typeclasses.solve
      public_key secret_key randomness
  in
  let public_key:t_Array u8 (mk_usize 32) = tmp0 in
  let secret_key:t_Array u8 (mk_usize 32) = tmp1 in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Libcrux_traits.Kem.Arrayref.t_KeyGenError
      #Anyhow.t_Error
      out
      (fun temp_0_ ->
          let _:Libcrux_traits.Kem.Arrayref.t_KeyGenError = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["X25519 key generation failed"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok _ ->
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

/// Generate a new DH key pair using X25519
let generate_dh_keypair
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error =
  let randomness:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  let public_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let secret_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (tmp1: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Libcrux_traits.Kem.Arrayref.t_KeyGenError) =
    Libcrux_traits.Kem.Arrayref.f_keygen #Libcrux_curve25519.t_X25519 #(mk_usize 32) #(mk_usize 32)
      #(mk_usize 32) #(mk_usize 32) #(mk_usize 32) #(mk_usize 32) #FStar.Tactics.Typeclasses.solve
      public_key secret_key randomness
  in
  let public_key:t_Array u8 (mk_usize 32) = tmp0 in
  let secret_key:t_Array u8 (mk_usize 32) = tmp1 in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Libcrux_traits.Kem.Arrayref.t_KeyGenError
      #Anyhow.t_Error
      out
      (fun temp_0_ ->
          let _:Libcrux_traits.Kem.Arrayref.t_KeyGenError = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["X25519 key generation failed"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok _ ->
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

/// Generate a random scalar for DH operations using X25519
let generate_random_scalar
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
  let randomness:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  let secret_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let e_public_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (tmp1: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Libcrux_traits.Kem.Arrayref.t_KeyGenError) =
    Libcrux_traits.Kem.Arrayref.f_keygen #Libcrux_curve25519.t_X25519 #(mk_usize 32) #(mk_usize 32)
      #(mk_usize 32) #(mk_usize 32) #(mk_usize 32) #(mk_usize 32) #FStar.Tactics.Typeclasses.solve
      e_public_key secret_key randomness
  in
  let e_public_key:t_Array u8 (mk_usize 32) = tmp0 in
  let secret_key:t_Array u8 (mk_usize 32) = tmp1 in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Libcrux_traits.Kem.Arrayref.t_KeyGenError
      #Anyhow.t_Error
      out
      (fun temp_0_ ->
          let _:Libcrux_traits.Kem.Arrayref.t_KeyGenError = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["X25519 key generation failed"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok _ ->
    let hax_temp_output:Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error =
      Core_models.Result.Result_Ok secret_key
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
    in
    rng, hax_temp_output
    <:
    (v_R & Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)

/// Convert a scalar to a DH public key using the X25519 standard generator base point
/// libcrux_curve25519::secret_to_public uses the standard X25519 base point G = 9
/// (defined as [9, 0, 0, 0, ...] in the HACL implementation, see `g25519` in their code)
let dh_public_key_from_scalar (scalar: t_Array u8 (mk_usize 32)) : t_DHPublicKey =
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public public_key_bytes scalar
  in
  impl_DHPublicKey__from_bytes public_key_bytes

/// Compute DH shared secret
let dh_shared_secret (public_key: t_DHPublicKey) (private_scalar: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result t_DHSharedSecret Anyhow.t_Error =
  let shared_secret_bytes:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Libcrux_curve25519.t_Error) =
    Libcrux_curve25519.Impl_hacl.ecdh shared_secret_bytes private_scalar public_key._0
  in
  let shared_secret_bytes:t_Array u8 (mk_usize 32) = tmp0 in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Libcrux_curve25519.t_Error
      #Anyhow.t_Error
      out
      (fun temp_0_ ->
          let _:Libcrux_curve25519.t_Error = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["X25519 DH failed"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok _ ->
    Core_models.Result.Result_Ok (DHSharedSecret shared_secret_bytes <: t_DHSharedSecret)
    <:
    Core_models.Result.t_Result t_DHSharedSecret Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_DHSharedSecret Anyhow.t_Error
