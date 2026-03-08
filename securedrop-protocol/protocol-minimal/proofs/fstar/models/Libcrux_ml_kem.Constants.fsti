module Libcrux_ml_kem.Constants
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// SHA3 256 digest size
let v_H_DIGEST_SIZE: usize = mk_usize 32
