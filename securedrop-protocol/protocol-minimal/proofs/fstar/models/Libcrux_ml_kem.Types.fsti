module Libcrux_ml_kem.Types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

///An ML-KEM Ciphertext
type t_MlKemCiphertext (v_SIZE: usize) = { f_value:t_Array u8 v_SIZE }

/// A reference to the raw byte slice.
val impl_7__as_slice (v_SIZE: usize) (self: t_MlKemCiphertext v_SIZE)
    : Prims.Pure (t_Array u8 v_SIZE)
      Prims.l_True
      (ensures
        fun result ->
          let result:t_Array u8 v_SIZE = result in
          result == self.f_value)

///An ML-KEM Private key
type t_MlKemPrivateKey (v_SIZE: usize) = { f_value:t_Array u8 v_SIZE }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_14 (v_SIZE: usize)
    : Core_models.Convert.t_From (t_MlKemPrivateKey v_SIZE) (t_Array u8 v_SIZE)

/// A reference to the raw byte slice.
val impl_15__as_slice (v_SIZE: usize) (self: t_MlKemPrivateKey v_SIZE)
    : Prims.Pure (t_Array u8 v_SIZE)
      Prims.l_True
      (ensures
        fun result ->
          let result:t_Array u8 v_SIZE = result in
          result == self.f_value)

///An ML-KEM Public key
type t_MlKemPublicKey (v_SIZE: usize) = { f_value:t_Array u8 v_SIZE }

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_22 (v_SIZE: usize)
    : Core_models.Convert.t_From (t_MlKemPublicKey v_SIZE) (t_Array u8 v_SIZE)

/// A reference to the raw byte slice.
val impl_23__as_slice (v_SIZE: usize) (self: t_MlKemPublicKey v_SIZE)
    : Prims.Pure (t_Array u8 v_SIZE)
      Prims.l_True
      (ensures
        fun result ->
          let result:t_Array u8 v_SIZE = result in
          result == self.f_value)

/// An ML-KEM key pair
type t_MlKemKeyPair (v_PRIVATE_KEY_SIZE: usize) (v_PUBLIC_KEY_SIZE: usize) = {
  f_sk:t_MlKemPrivateKey v_PRIVATE_KEY_SIZE;
  f_pk:t_MlKemPublicKey v_PUBLIC_KEY_SIZE
}

/// Separate this key into the public and private key.
val impl_24__into_parts
      (v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE: usize)
      (self: t_MlKemKeyPair v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE)
    : Prims.Pure (t_MlKemPrivateKey v_PRIVATE_KEY_SIZE & t_MlKemPublicKey v_PUBLIC_KEY_SIZE)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// Create a new [`MlKemKeyPair`] from the secret and public key.
val impl_24__from
      (v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE: usize)
      (sk: t_MlKemPrivateKey v_PRIVATE_KEY_SIZE)
      (pk: t_MlKemPublicKey v_PUBLIC_KEY_SIZE)
    : Prims.Pure (t_MlKemKeyPair v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE)
      Prims.l_True
      (ensures
        fun result ->
          let result:t_MlKemKeyPair v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE = result in
          result.f_sk == sk /\ result.f_pk == pk)
