module Libcrux_ml_kem.Matrix
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ml_kem.Hash_functions in
  let open Libcrux_ml_kem.Vector.Traits in
  ()

val sample_matrix_A
      (v_K: usize)
      (#v_Vector #v_Hasher: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      {| i1: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      (v_A_transpose:
          t_Array (t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K) v_K)
      (seed: t_Array u8 (mk_usize 34))
      (transpose: bool)
    : Prims.Pure
      (t_Array (t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K) v_K)
      (requires Spec.MLKEM.is_rank v_K)
      (ensures
        fun v_A_transpose_future ->
          let v_A_transpose_future:t_Array
            (t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K) v_K =
            v_A_transpose_future
          in
          let matrix_A, valid = Spec.MLKEM.sample_matrix_A_ntt (Seq.slice seed 0 32) in
          valid ==>
          (if transpose
            then Libcrux_ml_kem.Polynomial.to_spec_matrix_t v_A_transpose_future == matrix_A
            else
              Libcrux_ml_kem.Polynomial.to_spec_matrix_t v_A_transpose_future ==
              Spec.MLKEM.matrix_transpose matrix_A))

/// Compute Â ◦ ŝ + ê
val compute_As_plus_e
      (v_K: usize)
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (tt_as_ntt: t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
      (matrix_A:
          t_Array (t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K) v_K)
      (s_as_ntt error_as_ntt:
          t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
    : Prims.Pure (t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
      (requires Spec.MLKEM.is_rank v_K)
      (ensures
        fun tt_as_ntt_future ->
          let tt_as_ntt_future:t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector)
            v_K =
            tt_as_ntt_future
          in
          let open Libcrux_ml_kem.Polynomial in
          to_spec_vector_t tt_as_ntt_future =
          Spec.MLKEM.compute_As_plus_e_ntt (to_spec_matrix_t matrix_A)
            (to_spec_vector_t s_as_ntt)
            (to_spec_vector_t error_as_ntt) /\
          (forall (i: nat).
              i < v v_K ==>
              Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index tt_as_ntt_future i)))
