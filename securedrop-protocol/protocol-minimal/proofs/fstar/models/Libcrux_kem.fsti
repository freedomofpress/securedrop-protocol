module Libcrux_kem
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ecdh.P256_internal in
  let open Libcrux_ecdh.X25519 in
  let open Libcrux_ml_kem.Types in
  let open Rand.Rng in
  let open Rand_core in
  ()

/// KEM Algorithms
/// This includes named elliptic curves or dedicated KEM algorithms like ML-KEM.
type t_Algorithm =
  | Algorithm_X25519 : t_Algorithm
  | Algorithm_X448 : t_Algorithm
  | Algorithm_Secp256r1 : t_Algorithm
  | Algorithm_Secp384r1 : t_Algorithm
  | Algorithm_Secp521r1 : t_Algorithm
  | Algorithm_MlKem512 : t_Algorithm
  | Algorithm_MlKem768 : t_Algorithm
  | Algorithm_X25519MlKem768Draft00 : t_Algorithm
  | Algorithm_XWingKemDraft06 : t_Algorithm
  | Algorithm_MlKem1024 : t_Algorithm

val t_Algorithm_cast_to_repr (x: t_Algorithm)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)

let impl_13: Core_models.Clone.t_Clone t_Algorithm =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_14:Core_models.Marker.t_Copy t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_15:Core_models.Marker.t_StructuralPartialEq t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_16:Core_models.Cmp.t_PartialEq t_Algorithm t_Algorithm

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_17:Core_models.Fmt.t_Debug t_Algorithm

type t_Error =
  | Error_EcDhError : Libcrux_ecdh.t_Error -> t_Error
  | Error_KeyGen : t_Error
  | Error_Encapsulate : t_Error
  | Error_Decapsulate : t_Error
  | Error_UnsupportedAlgorithm : t_Error
  | Error_InvalidPrivateKey : t_Error
  | Error_InvalidPublicKey : t_Error
  | Error_InvalidCiphertext : t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_18:Core_models.Fmt.t_Debug t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_19:Core_models.Marker.t_StructuralPartialEq t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_20:Core_models.Cmp.t_PartialEq t_Error t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_21:Core_models.Cmp.t_Eq t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Core_models.Convert.t_TryFrom Libcrux_ecdh.t_Algorithm t_Algorithm =
  {
    f_Error = string;
    f_try_from_pre = (fun (value: t_Algorithm) -> true);
    f_try_from_post
    =
    (fun (value: t_Algorithm) (out: Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string) ->
        true);
    f_try_from
    =
    fun (value: t_Algorithm) ->
      match value <: t_Algorithm with
      | Algorithm_X25519  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_X25519 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | Algorithm_X448  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_X448 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | Algorithm_Secp256r1  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_P256 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | Algorithm_Secp384r1  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_P384 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | Algorithm_Secp521r1  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_P521 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | Algorithm_X25519MlKem768Draft00  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_X25519 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | Algorithm_XWingKemDraft06  ->
        Core_models.Result.Result_Ok (Libcrux_ecdh.Algorithm_X25519 <: Libcrux_ecdh.t_Algorithm)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
      | _ ->
        Core_models.Result.Result_Err "provided algorithm is not an ECDH algorithm"
        <:
        Core_models.Result.t_Result Libcrux_ecdh.t_Algorithm string
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_1:Core_models.Convert.t_From t_Error Libcrux_ecdh.t_Error

/// An ML-KEM768-x25519 private key.
type t_X25519MlKem768Draft00PrivateKey = {
  f_mlkem:Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 2400);
  f_x25519:Libcrux_ecdh.X25519.t_PrivateKey
}

/// An X-Wing private key.
type t_XWingKemDraft06PrivateKey = { f_seed:t_Array u8 (mk_usize 32) }

/// A KEM private key.
type t_PrivateKey =
  | PrivateKey_X25519 : Libcrux_ecdh.X25519.t_PrivateKey -> t_PrivateKey
  | PrivateKey_P256 : Libcrux_ecdh.P256_internal.t_PrivateKey -> t_PrivateKey
  | PrivateKey_MlKem512 : Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 1632) -> t_PrivateKey
  | PrivateKey_MlKem768 : Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 2400) -> t_PrivateKey
  | PrivateKey_X25519MlKem768Draft00 : t_X25519MlKem768Draft00PrivateKey -> t_PrivateKey
  | PrivateKey_XWingKemDraft06 : t_XWingKemDraft06PrivateKey -> t_PrivateKey
  | PrivateKey_MlKem1024 : Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 3168) -> t_PrivateKey

/// An ML-KEM768-x25519 public key.
type t_X25519MlKem768Draft00PublicKey = {
  f_mlkem:Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184);
  f_x25519:Libcrux_ecdh.X25519.t_PublicKey
}

/// An X-Wing public key.
type t_XWingKemDraft06PublicKey = {
  f_pk_m:Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184);
  f_pk_x:Libcrux_ecdh.X25519.t_PublicKey
}

/// A KEM public key.
type t_PublicKey =
  | PublicKey_X25519 : Libcrux_ecdh.X25519.t_PublicKey -> t_PublicKey
  | PublicKey_P256 : Libcrux_ecdh.P256_internal.t_PublicKey -> t_PublicKey
  | PublicKey_MlKem512 : Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 800) -> t_PublicKey
  | PublicKey_MlKem768 : Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184) -> t_PublicKey
  | PublicKey_X25519MlKem768Draft00 : t_X25519MlKem768Draft00PublicKey -> t_PublicKey
  | PublicKey_XWingKemDraft06 : t_XWingKemDraft06PublicKey -> t_PublicKey
  | PublicKey_MlKem1024 : Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1568) -> t_PublicKey

/// A KEM ciphertext
type t_Ct =
  | Ct_X25519 : Libcrux_ecdh.X25519.t_PublicKey -> t_Ct
  | Ct_P256 : Libcrux_ecdh.P256_internal.t_PublicKey -> t_Ct
  | Ct_MlKem512 : Libcrux_ml_kem.Types.t_MlKemCiphertext (mk_usize 768) -> t_Ct
  | Ct_MlKem768 : Libcrux_ml_kem.Types.t_MlKemCiphertext (mk_usize 1088) -> t_Ct
  | Ct_X25519MlKem768Draft00 :
      Libcrux_ml_kem.Types.t_MlKemCiphertext (mk_usize 1088) ->
      Libcrux_ecdh.X25519.t_PublicKey
    -> t_Ct
  | Ct_XWingKemDraft06 :
      Libcrux_ml_kem.Types.t_MlKemCiphertext (mk_usize 1088) ->
      Libcrux_ecdh.X25519.t_PublicKey
    -> t_Ct
  | Ct_MlKem1024 : Libcrux_ml_kem.Types.t_MlKemCiphertext (mk_usize 1568) -> t_Ct

/// A KEM shared secret
type t_Ss =
  | Ss_X25519 : Libcrux_ecdh.X25519.t_SharedSecret -> t_Ss
  | Ss_P256 : Libcrux_ecdh.P256_internal.t_SharedSecret -> t_Ss
  | Ss_MlKem512 : t_Array u8 (mk_usize 32) -> t_Ss
  | Ss_MlKem768 : t_Array u8 (mk_usize 32) -> t_Ss
  | Ss_X25519MlKem768Draft00 : t_Array u8 (mk_usize 32) -> Libcrux_ecdh.X25519.t_SharedSecret
    -> t_Ss
  | Ss_XWingKemDraft06 : Libcrux_kem.Xwing.t_XWingSharedSecret -> t_Ss
  | Ss_MlKem1024 : t_Array u8 (mk_usize 32) -> t_Ss

/// Compute the public key for a private key of the given [`Algorithm`].
/// Applicable only to X25519 and secp256r1.
val secret_to_public
      (#iimpl_677085834_: Type0)
      {| i0: Core_models.Convert.t_AsRef iimpl_677085834_ (t_Slice u8) |}
      (alg: t_Algorithm)
      (sk: iimpl_677085834_)
    : Prims.Pure (Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

val random_array
      (v_L: usize)
      (#iimpl_447424039_: Type0)
      {| i0: Rand_core.t_CryptoRng iimpl_447424039_ |}
      (rng: iimpl_447424039_)
    : Prims.Pure (iimpl_447424039_ & Core_models.Result.t_Result (t_Array u8 v_L) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

val gen_mlkem768
      (#iimpl_447424039_: Type0)
      {| i0: Rand_core.t_CryptoRng iimpl_447424039_ |}
      (rng: iimpl_447424039_)
    : Prims.Pure
      (iimpl_447424039_ &
        Core_models.Result.t_Result
          (Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 2400) &
            Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184)) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Generate a key pair for the [`Algorithm`] using the provided rng.
/// The function returns a fresh key or a [`Error::KeyGen`] error if
/// * not enough entropy was available
/// * it was not possible to generate a valid key within a reasonable amount of iterations.
val key_gen
      (#iimpl_447424039_: Type0)
      {| i0: Rand_core.t_CryptoRng iimpl_447424039_ |}
      (alg: t_Algorithm)
      (rng: iimpl_447424039_)
    : Prims.Pure
      (iimpl_447424039_ & Core_models.Result.t_Result (t_PrivateKey & t_PublicKey) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Generate a key pair for the [`Algorithm`] using the provided rng.
/// The function returns a fresh key or a [`Error::KeyGen`] error if
/// * the `seed` wasn't long enough
/// * it was not possible to generate a valid key within a reasonable amount of iterations.
val key_gen_derand (alg: t_Algorithm) (seed: t_Slice u8)
    : Prims.Pure (Core_models.Result.t_Result (t_PrivateKey & t_PublicKey) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

val mlkem_rand
      (#iimpl_447424039_: Type0)
      {| i0: Rand_core.t_CryptoRng iimpl_447424039_ |}
      (rng: iimpl_447424039_)
    : Prims.Pure (iimpl_447424039_ & Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_11: Core_models.Convert.t_TryInto t_PublicKey Libcrux_ecdh.X25519.t_PublicKey =
  {
    f_Error = Libcrux_ecdh.t_Error;
    f_try_into_pre = (fun (self: t_PublicKey) -> true);
    f_try_into_post
    =
    (fun
        (self: t_PublicKey)
        (out: Core_models.Result.t_Result Libcrux_ecdh.X25519.t_PublicKey Libcrux_ecdh.t_Error)
        ->
        true);
    f_try_into
    =
    fun (self: t_PublicKey) ->
      match self <: t_PublicKey with
      | PublicKey_X25519 k ->
        Core_models.Result.Result_Ok k
        <:
        Core_models.Result.t_Result Libcrux_ecdh.X25519.t_PublicKey Libcrux_ecdh.t_Error
      | _ ->
        Core_models.Result.Result_Err (Libcrux_ecdh.Error_InvalidPoint <: Libcrux_ecdh.t_Error)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.X25519.t_PublicKey Libcrux_ecdh.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_12: Core_models.Convert.t_TryInto t_PrivateKey Libcrux_ecdh.X25519.t_PrivateKey =
  {
    f_Error = Libcrux_ecdh.t_Error;
    f_try_into_pre = (fun (self: t_PrivateKey) -> true);
    f_try_into_post
    =
    (fun
        (self: t_PrivateKey)
        (out: Core_models.Result.t_Result Libcrux_ecdh.X25519.t_PrivateKey Libcrux_ecdh.t_Error)
        ->
        true);
    f_try_into
    =
    fun (self: t_PrivateKey) ->
      match self <: t_PrivateKey with
      | PrivateKey_X25519 k ->
        Core_models.Result.Result_Ok k
        <:
        Core_models.Result.t_Result Libcrux_ecdh.X25519.t_PrivateKey Libcrux_ecdh.t_Error
      | _ ->
        Core_models.Result.Result_Err (Libcrux_ecdh.Error_InvalidPoint <: Libcrux_ecdh.t_Error)
        <:
        Core_models.Result.t_Result Libcrux_ecdh.X25519.t_PrivateKey Libcrux_ecdh.t_Error
  }
