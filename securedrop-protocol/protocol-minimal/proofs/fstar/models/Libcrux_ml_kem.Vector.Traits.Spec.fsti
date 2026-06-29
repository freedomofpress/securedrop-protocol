module Libcrux_ml_kem.Vector.Traits.Spec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

val add_pre (lhs rhs: t_Array i16 (mk_usize 16))
    : Prims.Pure Hax_lib.Prop.t_Prop Prims.l_True (fun _ -> Prims.l_True)

val add_post (lhs rhs result: t_Array i16 (mk_usize 16))
    : Prims.Pure Hax_lib.Prop.t_Prop Prims.l_True (fun _ -> Prims.l_True)
