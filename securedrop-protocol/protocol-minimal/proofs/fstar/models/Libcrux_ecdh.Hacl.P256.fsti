module Libcrux_ecdh.Hacl.P256
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_Error =
  | Error_InvalidInput : t_Error
  | Error_InvalidScalar : t_Error
  | Error_InvalidPoint : t_Error
  | Error_NoCompressedPoint : t_Error
  | Error_NoUnCompressedPoint : t_Error
