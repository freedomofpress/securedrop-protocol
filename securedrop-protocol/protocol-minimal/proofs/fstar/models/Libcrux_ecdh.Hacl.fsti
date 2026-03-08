module Libcrux_ecdh.Hacl
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Unified error type.
type t_Error =
  | Error_Curve25519 : Libcrux_ecdh.Hacl.Curve25519.t_Error -> t_Error
  | Error_P256 : Libcrux_ecdh.Hacl.P256.t_Error -> t_Error
