module Libcrux_curve25519.Impl_hacl
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

val secret_to_public (pk sk: t_Array u8 (mk_usize 32))
    : Prims.Pure (t_Array u8 (mk_usize 32)) Prims.l_True (fun _ -> Prims.l_True)

val ecdh (out pk sk: t_Array u8 (mk_usize 32))
    : Prims.Pure
      (t_Array u8 (mk_usize 32) & Core_models.Result.t_Result Prims.unit Libcrux_curve25519.t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)
