module Securedrop_protocol_minimal.Primitives.Provider.Params.Chacha20poly1305
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
val v_KEY_LEN': usize

unfold
let v_KEY_LEN = v_KEY_LEN'

assume
val v_NONCE_LEN': usize

unfold
let v_NONCE_LEN = v_NONCE_LEN'

assume
val v_TAG_LEN': usize

unfold
let v_TAG_LEN = v_TAG_LEN'
