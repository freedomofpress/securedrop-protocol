module Libcrux_ml_kem.Mlkem768
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  let open Libcrux_traits.Kem.Owned in
  ()

/// Marker/provider type selecting ML-KEM-768.
assume
type t_MlKem768 : Type0

/// `Kem` instance for ML-KEM-768:
///   PK = 1184, SK = 2400, CT = 1088, SS = 32,
///   keygen seed = 64, encaps randomness = 32.
[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_Kem_MlKem768
    : Libcrux_traits.Kem.Owned.t_Kem
        t_MlKem768
        (mk_usize 1184)
        (mk_usize 2400)
        (mk_usize 1088)
        (mk_usize 32)
        (mk_usize 64)
        (mk_usize 32)
