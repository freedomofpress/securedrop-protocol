module Libcrux_ecdh
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_LowLevelError =
  | LowLevelError_Jasmin : Alloc.String.t_String -> t_LowLevelError
  | LowLevelError_Hacl : Libcrux_ecdh.Hacl.t_Error -> t_LowLevelError

type t_Error =
  | Error_InvalidPoint : t_Error
  | Error_InvalidScalar : t_Error
  | Error_UnknownAlgorithm : t_Error
  | Error_KeyGenError : t_Error
  | Error_Custom : Alloc.String.t_String -> t_Error
  | Error_Wrap : t_LowLevelError -> t_Error
