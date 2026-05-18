module Libcrux_ml_kem.Ind_cca.Multiplexing
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

val generate_keypair
      (v_K v_CPA_PRIVATE_KEY_SIZE v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE v_ETA1 v_ETA1_RANDOMNESS_SIZE:
          usize)
      (randomness: t_Array u8 (mk_usize 64))
    : Prims.Pure (Libcrux_ml_kem.Types.t_MlKemKeyPair v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_CPA_PRIVATE_KEY_SIZE == Spec.MLKEM.v_CPA_PRIVATE_KEY_SIZE v_K /\
        v_PRIVATE_KEY_SIZE == Spec.MLKEM.v_CCA_PRIVATE_KEY_SIZE v_K /\
        v_PUBLIC_KEY_SIZE == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\ v_ETA1 == Spec.MLKEM.v_ETA1 v_K /\
        v_ETA1_RANDOMNESS_SIZE == Spec.MLKEM.v_ETA1_RANDOMNESS_SIZE v_K)
      (fun _ -> Prims.l_True)
