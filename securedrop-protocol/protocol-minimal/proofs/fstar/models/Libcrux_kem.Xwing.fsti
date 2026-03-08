module Libcrux_kem.Xwing
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_XWingSharedSecret = { f_value:t_Array u8 (mk_usize 32) }
