module Libcrux_ml_kem.Mlkem768
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// The ML-KEM 768 algorithms
type t_MlKem768 = | MlKem768 : t_MlKem768

/// Axiomatic stub: hax cannot extract this typeclass instance because libcrux's
/// `arrayref::Kem` impl on `MlKem768` is `#[hax_lib::exclude]`-marked, and the
/// blanket `impl<T: arrayref::Kem> owned::Kem for T` in libcrux/traits uses
/// `&mut`, which hax rejects (HAX0003 DirectAndMut).
[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_Kem_owned_MlKem768
    : Libcrux_traits.Kem.Owned.t_Kem
        t_MlKem768
        (mk_usize 1184) (mk_usize 2400) (mk_usize 1088)
        (mk_usize 32) (mk_usize 64) (mk_usize 32)
