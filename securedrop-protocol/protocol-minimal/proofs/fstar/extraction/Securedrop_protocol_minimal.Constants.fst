module Securedrop_protocol_minimal.Constants
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let v_LEN_DHKEM_DECAPS_KEY: usize = Libcrux_curve25519.v_DK_LEN

let v_LEN_DH_ITEM: usize = v_LEN_DHKEM_DECAPS_KEY

let v_LEN_XWING_ENCAPS_KEY: usize = mk_usize 1216
