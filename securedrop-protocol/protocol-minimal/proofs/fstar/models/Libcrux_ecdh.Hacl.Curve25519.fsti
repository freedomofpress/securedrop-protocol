module Libcrux_ecdh.Hacl.Curve25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_Error = | Error_InvalidInput : t_Error
