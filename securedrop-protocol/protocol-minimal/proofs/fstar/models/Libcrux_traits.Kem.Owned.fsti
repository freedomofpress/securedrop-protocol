module Libcrux_traits.Kem.Owned
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A Key Encapsulation Mechanismd (KEM) that returns values instead of writing the results to
/// `&mut` arguments.
class t_Kem
  (v_Self: Type0) (v_EK_LEN: usize) (v_DK_LEN: usize) (v_CT_LEN: usize) (v_SS_LEN: usize)
  (v_RAND_KEYGEN_LEN: usize) (v_RAND_ENCAPS_LEN: usize)
  = {
  f_keygen_pre:t_Array u8 v_RAND_KEYGEN_LEN -> Type0;
  f_keygen_post:
      t_Array u8 v_RAND_KEYGEN_LEN ->
      Core_models.Result.t_Result (t_Array u8 v_DK_LEN & t_Array u8 v_EK_LEN)
          Libcrux_traits.Kem.Arrayref.t_KeyGenError
    -> Type0;
  f_keygen:x0: t_Array u8 v_RAND_KEYGEN_LEN
    -> Prims.Pure
        (Core_models.Result.t_Result (t_Array u8 v_DK_LEN & t_Array u8 v_EK_LEN)
            Libcrux_traits.Kem.Arrayref.t_KeyGenError)
        (f_keygen_pre x0)
        (fun result -> f_keygen_post x0 result);
  f_encaps_pre:t_Array u8 v_EK_LEN -> t_Array u8 v_RAND_ENCAPS_LEN -> Type0;
  f_encaps_post:
      t_Array u8 v_EK_LEN ->
      t_Array u8 v_RAND_ENCAPS_LEN ->
      Core_models.Result.t_Result (t_Array u8 v_SS_LEN & t_Array u8 v_CT_LEN)
          Libcrux_traits.Kem.Arrayref.t_EncapsError
    -> Type0;
  f_encaps:x0: t_Array u8 v_EK_LEN -> x1: t_Array u8 v_RAND_ENCAPS_LEN
    -> Prims.Pure
        (Core_models.Result.t_Result (t_Array u8 v_SS_LEN & t_Array u8 v_CT_LEN)
            Libcrux_traits.Kem.Arrayref.t_EncapsError)
        (f_encaps_pre x0 x1)
        (fun result -> f_encaps_post x0 x1 result);
  f_decaps_pre:t_Array u8 v_CT_LEN -> t_Array u8 v_DK_LEN -> Type0;
  f_decaps_post:
      t_Array u8 v_CT_LEN ->
      t_Array u8 v_DK_LEN ->
      Core_models.Result.t_Result (t_Array u8 v_SS_LEN) Libcrux_traits.Kem.Arrayref.t_DecapsError
    -> Type0;
  f_decaps:x0: t_Array u8 v_CT_LEN -> x1: t_Array u8 v_DK_LEN
    -> Prims.Pure
        (Core_models.Result.t_Result (t_Array u8 v_SS_LEN) Libcrux_traits.Kem.Arrayref.t_DecapsError
        ) (f_decaps_pre x0 x1) (fun result -> f_decaps_post x0 x1 result)
}
