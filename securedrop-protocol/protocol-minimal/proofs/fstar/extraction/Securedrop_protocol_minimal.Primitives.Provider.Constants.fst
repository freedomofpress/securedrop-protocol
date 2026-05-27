module Securedrop_protocol_minimal.Primitives.Provider.Constants
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
val v_LEN_MESSAGE_ID': usize

unfold
let v_LEN_MESSAGE_ID = v_LEN_MESSAGE_ID'

assume
val v_LEN_KMID': usize

unfold
let v_LEN_KMID = v_LEN_KMID'
