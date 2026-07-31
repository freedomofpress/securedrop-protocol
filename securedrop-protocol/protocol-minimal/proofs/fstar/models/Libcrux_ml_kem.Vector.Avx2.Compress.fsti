module Libcrux_ml_kem.Vector.Avx2.Compress
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

val mulhi_mm256_epi32 (lhs rhs: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      Prims.l_True
      (fun _ -> Prims.l_True)

val compress_message_coefficient (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      Prims.l_True
      (fun _ -> Prims.l_True)

val compress_ciphertext_coefficient
      (v_COEFFICIENT_BITS: i32)
      (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires
        v v_COEFFICIENT_BITS >= 0 /\ v v_COEFFICIENT_BITS < bits i32_inttype /\
        range (v ((mk_i32 1) <<! v_COEFFICIENT_BITS) - 1) i32_inttype)
      (fun _ -> Prims.l_True)

val decompress_1_ (a: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires
        forall i.
          let x = Seq.index (Libcrux_intrinsics.Avx2_extract.vec256_as_i16x16 a) i in
          (x == mk_i16 0 \/ x == mk_i16 1))
      (fun _ -> Prims.l_True)

val decompress_ciphertext_coefficient
      (v_COEFFICIENT_BITS: i32)
      (vector: Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
    : Prims.Pure (Core_models.Abstractions.Bitvec.t_BitVec (mk_u64 256))
      (requires v v_COEFFICIENT_BITS >= 0 /\ v v_COEFFICIENT_BITS < bits i32_inttype)
      (fun _ -> Prims.l_True)
