module Securedrop_protocol_minimal.Primitives.Provider.Hkdf
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// HKDF-SHA256
assume
val sha256': okm: t_Slice u8 -> salt: t_Slice u8 -> ikm: t_Slice u8 -> info: t_Slice u8
  -> (t_Slice u8 & Core_models.Result.t_Result Prims.unit Libcrux_hkdf.t_ExpandError)

unfold
let sha256 = sha256'
