module Libcrux_traits.Kem.Arrayref
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Error generating key with provided randomness
type t_KeyGenError =
  | KeyGenError_InvalidRandomness : t_KeyGenError
  | KeyGenError_Unknown : t_KeyGenError

val t_KeyGenError_cast_to_repr (x: t_KeyGenError)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)

/// Error indicating that encapsulating failed
type t_EncapsError =
  | EncapsError_InvalidEncapsKey : t_EncapsError
  | EncapsError_InvalidRandomness : t_EncapsError
  | EncapsError_Unknown : t_EncapsError

val t_EncapsError_cast_to_repr (x: t_EncapsError)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)

/// Error indicating that decapsulating failed
type t_DecapsError =
  | DecapsError_InvalidCiphertext : t_DecapsError
  | DecapsError_InvalidDecapsKey : t_DecapsError
  | DecapsError_Unknown : t_DecapsError

/// A Key Encapsulation Mechanism (KEM). This trait is the most low-level and mostly used in the
/// implementation of other, more usabe APIs on top.
class t_Kem
  (v_Self: Type0) (v_EK_LEN: usize) (v_DK_LEN: usize) (v_CT_LEN: usize) (v_SS_LEN: usize)
  (v_RAND_KEYGEN_LEN: usize) (v_RAND_ENCAPS_LEN: usize)
  = {
  f_keygen_pre:t_Array u8 v_EK_LEN -> t_Array u8 v_DK_LEN -> t_Array u8 v_RAND_KEYGEN_LEN -> Type0;
  f_keygen_post:
      t_Array u8 v_EK_LEN ->
      t_Array u8 v_DK_LEN ->
      t_Array u8 v_RAND_KEYGEN_LEN ->
      (t_Array u8 v_EK_LEN & t_Array u8 v_DK_LEN &
          Core_models.Result.t_Result Prims.unit t_KeyGenError)
    -> Type0;
  f_keygen:x0: t_Array u8 v_EK_LEN -> x1: t_Array u8 v_DK_LEN -> x2: t_Array u8 v_RAND_KEYGEN_LEN
    -> Prims.Pure
        (t_Array u8 v_EK_LEN & t_Array u8 v_DK_LEN &
          Core_models.Result.t_Result Prims.unit t_KeyGenError)
        (f_keygen_pre x0 x1 x2)
        (fun result -> f_keygen_post x0 x1 x2 result);
  f_encaps_pre:
      t_Array u8 v_CT_LEN ->
      t_Array u8 v_SS_LEN ->
      t_Array u8 v_EK_LEN ->
      t_Array u8 v_RAND_ENCAPS_LEN
    -> Type0;
  f_encaps_post:
      t_Array u8 v_CT_LEN ->
      t_Array u8 v_SS_LEN ->
      t_Array u8 v_EK_LEN ->
      t_Array u8 v_RAND_ENCAPS_LEN ->
      (t_Array u8 v_CT_LEN & t_Array u8 v_SS_LEN &
          Core_models.Result.t_Result Prims.unit t_EncapsError)
    -> Type0;
  f_encaps:
      x0: t_Array u8 v_CT_LEN ->
      x1: t_Array u8 v_SS_LEN ->
      x2: t_Array u8 v_EK_LEN ->
      x3: t_Array u8 v_RAND_ENCAPS_LEN
    -> Prims.Pure
        (t_Array u8 v_CT_LEN & t_Array u8 v_SS_LEN &
          Core_models.Result.t_Result Prims.unit t_EncapsError)
        (f_encaps_pre x0 x1 x2 x3)
        (fun result -> f_encaps_post x0 x1 x2 x3 result);
  f_decaps_pre:t_Array u8 v_SS_LEN -> t_Array u8 v_CT_LEN -> t_Array u8 v_DK_LEN -> Type0;
  f_decaps_post:
      t_Array u8 v_SS_LEN ->
      t_Array u8 v_CT_LEN ->
      t_Array u8 v_DK_LEN ->
      (t_Array u8 v_SS_LEN & Core_models.Result.t_Result Prims.unit t_DecapsError)
    -> Type0;
  f_decaps:x0: t_Array u8 v_SS_LEN -> x1: t_Array u8 v_CT_LEN -> x2: t_Array u8 v_DK_LEN
    -> Prims.Pure (t_Array u8 v_SS_LEN & Core_models.Result.t_Result Prims.unit t_DecapsError)
        (f_decaps_pre x0 x1 x2)
        (fun result -> f_decaps_post x0 x1 x2 result)
}

val t_DecapsError_cast_to_repr (x: t_DecapsError)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)
