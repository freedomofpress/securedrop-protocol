module Libcrux_ml_kem.Vector.Avx2.Ntt
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

val ntt_layer_1_step
      (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (zeta0 zeta1 zeta2 zeta3: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires
        Spec.Utils.is_i16b 1664 zeta0 /\ Spec.Utils.is_i16b 1664 zeta1 /\
        Spec.Utils.is_i16b 1664 zeta2 /\ Spec.Utils.is_i16b 1664 zeta3)
      (fun _ -> Prims.l_True)

val ntt_layer_2_step
      (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (zeta0 zeta1: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires Spec.Utils.is_i16b 1664 zeta0 /\ Spec.Utils.is_i16b 1664 zeta1)
      (fun _ -> Prims.l_True)

val ntt_layer_3_step (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256)) (zeta: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires Spec.Utils.is_i16b 1664 zeta)
      (fun _ -> Prims.l_True)

val inv_ntt_layer_1_step
      (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (zeta0 zeta1 zeta2 zeta3: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires
        Spec.Utils.is_i16b 1664 zeta0 /\ Spec.Utils.is_i16b 1664 zeta1 /\
        Spec.Utils.is_i16b 1664 zeta2 /\ Spec.Utils.is_i16b 1664 zeta3 /\
        Spec.Utils.is_i16b_array (4 * 3328)
          (Libcrux_intrinsics.Avx2_extract.vec256_as_i16x16 vector))
      (fun _ -> Prims.l_True)

val inv_ntt_layer_2_step
      (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (zeta0 zeta1: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires Spec.Utils.is_i16b 1664 zeta0 /\ Spec.Utils.is_i16b 1664 zeta1)
      (fun _ -> Prims.l_True)

val inv_ntt_layer_3_step (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256)) (zeta: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires Spec.Utils.is_i16b 1664 zeta)
      (fun _ -> Prims.l_True)

val ntt_multiply
      (lhs rhs: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (zeta0 zeta1 zeta2 zeta3: i16)
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires
        Spec.Utils.is_i16b 1664 zeta0 /\ Spec.Utils.is_i16b 1664 zeta1 /\
        Spec.Utils.is_i16b 1664 zeta2 /\ Spec.Utils.is_i16b 1664 zeta3)
      (fun _ -> Prims.l_True)
