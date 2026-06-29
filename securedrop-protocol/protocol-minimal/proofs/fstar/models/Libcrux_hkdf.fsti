module Libcrux_hkdf
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_ExpandError =
  | ExpandError_OutputTooLong : t_ExpandError
  | ExpandError_PrkTooShort : t_ExpandError
  | ExpandError_ArgumentTooLong : t_ExpandError
  | ExpandError_Unknown : t_ExpandError

val t_ExpandError_cast_to_repr (x: t_ExpandError)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)
