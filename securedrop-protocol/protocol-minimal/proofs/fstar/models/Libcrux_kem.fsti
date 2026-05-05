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

type t_Error =
  | Error_EcDhError : Libcrux_ecdh.t_Error -> t_Error
  | Error_KeyGen : t_Error
  | Error_Encapsulate : t_Error
  | Error_Decapsulate : t_Error
  | Error_UnsupportedAlgorithm : t_Error
  | Error_InvalidPrivateKey : t_Error
  | Error_InvalidPublicKey : t_Error
  | Error_InvalidCiphertext : t_Error

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

/// Encode a private key.
val impl_PrivateKey__encode (self: t_PrivateKey)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Prims.l_True (fun _ -> Prims.l_True)

/// Decode a private key.
val impl_PrivateKey__decode (alg: t_Algorithm) (bytes: t_Slice u8)
    : Prims.Pure (Core_models.Result.t_Result t_PrivateKey t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Encapsulate a shared secret to the provided `pk` and return the `(Key, Enc)` tuple.
val impl_PublicKey__encapsulate
      (#iimpl_447424039_: Type0)
      {| i0: Rand_core.t_CryptoRng iimpl_447424039_ |}
      (self: t_PublicKey)
      (rng: iimpl_447424039_)
    : Prims.Pure (iimpl_447424039_ & Core_models.Result.t_Result (t_Ss & t_Ct) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Encapsulate a shared secret to the provided `pk` and return the `(Key, Enc)` tuple.
val impl_PublicKey__encapsulate_derand (self: t_PublicKey) (seed: t_Slice u8)
    : Prims.Pure (Core_models.Result.t_Result (t_Ss & t_Ct) t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Encode public key.
val impl_PublicKey__encode (self: t_PublicKey)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Prims.l_True (fun _ -> Prims.l_True)

/// Decode a public key.
val impl_PublicKey__decode (alg: t_Algorithm) (bytes: t_Slice u8)
    : Prims.Pure (Core_models.Result.t_Result t_PublicKey t_Error)
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
