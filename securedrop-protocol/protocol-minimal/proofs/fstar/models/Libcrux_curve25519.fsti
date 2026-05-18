module Libcrux_curve25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// The length of Curve25519 secret keys.
let v_DK_LEN: usize = mk_usize 32

/// The length of Curve25519 public keys.
let v_EK_LEN: usize = mk_usize 32

/// The length of Curve25519 shared keys.
let v_SS_LEN: usize = mk_usize 32

/// Indicates that an error occurred
type t_Error = | Error : t_Error

type t_X25519 = | X25519 : t_X25519
