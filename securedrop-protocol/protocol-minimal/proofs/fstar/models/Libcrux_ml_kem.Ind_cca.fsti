module Libcrux_ml_kem.Ind_cca
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ml_kem.Hash_functions in
  let open Libcrux_ml_kem.Types in
  let open Libcrux_ml_kem.Variant in
  let open Libcrux_ml_kem.Vector.Traits in
  ()

/// Seed size for key generation
let v_KEY_GENERATION_SEED_SIZE: usize =
  Libcrux_ml_kem.Constants.v_CPA_PKE_KEY_GENERATION_SEED_SIZE +!
  Libcrux_ml_kem.Constants.v_SHARED_SECRET_SIZE

/// Serialize the secret key.
val serialize_kem_secret_key_mut
      (v_K v_SERIALIZED_KEY_LEN: usize)
      (#v_Hasher: Type0)
      {| i0: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      (private_key public_key implicit_rejection_value: t_Slice u8)
      (serialized: t_Array u8 v_SERIALIZED_KEY_LEN)
    : Prims.Pure (t_Array u8 v_SERIALIZED_KEY_LEN)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_SERIALIZED_KEY_LEN == Spec.MLKEM.v_CCA_PRIVATE_KEY_SIZE v_K /\
        Core_models.Slice.impl__len #u8 private_key == Spec.MLKEM.v_CPA_PRIVATE_KEY_SIZE v_K /\
        Core_models.Slice.impl__len #u8 public_key == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\
        Core_models.Slice.impl__len #u8 implicit_rejection_value == Spec.MLKEM.v_SHARED_SECRET_SIZE)
      (ensures
        fun serialized_future ->
          let serialized_future:t_Array u8 v_SERIALIZED_KEY_LEN = serialized_future in
          serialized_future ==
          Seq.append private_key
            (Seq.append public_key (Seq.append (Spec.Utils.v_H public_key) implicit_rejection_value)
            ))

val serialize_kem_secret_key
      (v_K v_SERIALIZED_KEY_LEN: usize)
      (#v_Hasher: Type0)
      {| i0: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      (private_key public_key implicit_rejection_value: t_Slice u8)
    : Prims.Pure (t_Array u8 v_SERIALIZED_KEY_LEN)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_SERIALIZED_KEY_LEN == Spec.MLKEM.v_CCA_PRIVATE_KEY_SIZE v_K /\
        Core_models.Slice.impl__len #u8 private_key == Spec.MLKEM.v_CPA_PRIVATE_KEY_SIZE v_K /\
        Core_models.Slice.impl__len #u8 public_key == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\
        Core_models.Slice.impl__len #u8 implicit_rejection_value == Spec.MLKEM.v_SHARED_SECRET_SIZE)
      (ensures
        fun result ->
          let result:t_Array u8 v_SERIALIZED_KEY_LEN = result in
          result ==
          Seq.append private_key
            (Seq.append public_key (Seq.append (Spec.Utils.v_H public_key) implicit_rejection_value)
            ))

/// Packed API
/// Generate a key pair.
/// Depending on the `Vector` and `Hasher` used, this requires different hardware
/// features
val generate_keypair
      (v_K v_CPA_PRIVATE_KEY_SIZE v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE v_ETA1 v_ETA1_RANDOMNESS_SIZE:
          usize)
      (#v_Vector #v_Hasher #v_Scheme: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      {| i1: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      {| i2: Libcrux_ml_kem.Variant.t_Variant v_Scheme |}
      (randomness: t_Array u8 (mk_usize 64))
    : Prims.Pure (Libcrux_ml_kem.Types.t_MlKemKeyPair v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_CPA_PRIVATE_KEY_SIZE == Spec.MLKEM.v_CPA_PRIVATE_KEY_SIZE v_K /\
        v_PRIVATE_KEY_SIZE == Spec.MLKEM.v_CCA_PRIVATE_KEY_SIZE v_K /\
        v_PUBLIC_KEY_SIZE == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\ v_ETA1 == Spec.MLKEM.v_ETA1 v_K /\
        v_ETA1_RANDOMNESS_SIZE == Spec.MLKEM.v_ETA1_RANDOMNESS_SIZE v_K)
      (ensures
        fun result ->
          let result:Libcrux_ml_kem.Types.t_MlKemKeyPair v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE =
            result
          in
          let expected, valid = Spec.MLKEM.ind_cca_generate_keypair v_K randomness in
          valid ==> (result.f_sk.f_value, result.f_pk.f_value) == expected)
