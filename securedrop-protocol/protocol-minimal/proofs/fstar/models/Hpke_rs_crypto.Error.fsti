module Hpke_rs_crypto.Error
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
type t_Error : Type0
