module Libcrux_traits.Kem.Owned
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  let open Libcrux_traits.Kem.Arrayref in
  ()

/// The `Kem` trait from `libcrux-traits::kem::owned`. A KEM is parameterised
/// by the byte lengths of its public key, secret key, ciphertext, shared
/// secret, key-generation seed, and encapsulation randomness.
class t_Kem
      (v_Self: Type0)
      (v_PK_LEN: usize)
      (v_SK_LEN: usize)
      (v_CT_LEN: usize)
      (v_SS_LEN: usize)
      (v_KEYGEN_RAND_LEN: usize)
      (v_ENCAPS_RAND_LEN: usize) = {
  f_encaps_pre:
      pk:t_Array u8 v_PK_LEN -> rand:t_Array u8 v_ENCAPS_RAND_LEN -> Type0;
  f_encaps_post:
      pk:t_Array u8 v_PK_LEN -> rand:t_Array u8 v_ENCAPS_RAND_LEN
    -> Core_models.Result.t_Result
         (t_Array u8 v_SS_LEN & t_Array u8 v_CT_LEN)
         Libcrux_traits.Kem.Arrayref.t_EncapsError
    -> Type0;
  f_encaps:
      x0:t_Array u8 v_PK_LEN -> x1:t_Array u8 v_ENCAPS_RAND_LEN
    -> Prims.Pure
         (Core_models.Result.t_Result
            (t_Array u8 v_SS_LEN & t_Array u8 v_CT_LEN)
            Libcrux_traits.Kem.Arrayref.t_EncapsError)
         (f_encaps_pre x0 x1)
         (fun r -> f_encaps_post x0 x1 r);

  f_decaps_pre:
      ct:t_Array u8 v_CT_LEN -> sk:t_Array u8 v_SK_LEN -> Type0;
  f_decaps_post:
      ct:t_Array u8 v_CT_LEN -> sk:t_Array u8 v_SK_LEN
    -> Core_models.Result.t_Result
         (t_Array u8 v_SS_LEN)
         Libcrux_traits.Kem.Arrayref.t_DecapsError
    -> Type0;
  f_decaps:
      x0:t_Array u8 v_CT_LEN -> x1:t_Array u8 v_SK_LEN
    -> Prims.Pure
         (Core_models.Result.t_Result
            (t_Array u8 v_SS_LEN)
            Libcrux_traits.Kem.Arrayref.t_DecapsError)
         (f_decaps_pre x0 x1)
         (fun r -> f_decaps_post x0 x1 r)
}
