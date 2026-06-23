module Libcrux_ml_kem.Serialize
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ml_kem.Vector.Traits in
  ()

val to_unsigned_field_modulus
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (a: v_Vector)
    : Prims.Pure v_Vector
      (requires Libcrux_ml_kem.Polynomial.is_bounded_vector 3328 a)
      (ensures
        fun result ->
          let result:v_Vector = result in
          forall (i: nat).
            i < 16 ==>
            v (Seq.index (Libcrux_ml_kem.Vector.Traits.f_to_i16_array result) i) >= 0 /\
            v (Seq.index (Libcrux_ml_kem.Vector.Traits.f_to_i16_array result) i) <
            v Libcrux_ml_kem.Vector.Traits.v_FIELD_MODULUS)

val serialize_uncompressed_ring_element
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (re: Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector)
    : Prims.Pure (t_Array u8 (mk_usize 384))
      (requires Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 re)
      (ensures
        fun result ->
          let result:t_Array u8 (mk_usize 384) = result in
          result ==
          Spec.MLKEM.byte_encode 12 (Libcrux_ml_kem.Polynomial.to_spec_poly_t #v_Vector re))
