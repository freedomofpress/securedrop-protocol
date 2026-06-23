module Securedrop_protocol_minimal.Primitives.Provider.Mlkem
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
val v_KEY_GENERATION_SEED_SIZE': usize

unfold
let v_KEY_GENERATION_SEED_SIZE = v_KEY_GENERATION_SEED_SIZE'
