module Securedrop_protocol_minimal.Primitives.Provider.Curve25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let v_SK_LEN: usize = Libcrux_curve25519.v_DK_LEN

let v_PK_LEN: usize = Libcrux_curve25519.v_EK_LEN

let v_LEN_DH_SHARE: usize = Libcrux_curve25519.v_SS_LEN
