module Securedrop_protocol_minimal.Primitives.Provider.Curve25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
val v_SK_LEN': usize

unfold
let v_SK_LEN = v_SK_LEN'

assume
val v_PK_LEN': usize

unfold
let v_PK_LEN = v_PK_LEN'
