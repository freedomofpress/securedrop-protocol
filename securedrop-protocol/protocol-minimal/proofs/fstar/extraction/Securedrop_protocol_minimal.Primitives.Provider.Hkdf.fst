module Securedrop_protocol_minimal.Primitives.Provider.Hkdf
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// HKDF-SHA256
assume
val sha256': okm: t_Slice u8 -> salt: t_Slice u8 -> ikm: t_Slice u8 -> info: t_Slice u8
  -> Prims.Pure (t_Slice u8 & Core_models.Result.t_Result Prims.unit Libcrux_hkdf.t_ExpandError)
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let
          (okm_future: t_Slice u8),
          (_: Core_models.Result.t_Result Prims.unit Libcrux_hkdf.t_ExpandError) =
            temp_0_
          in
          (Core_models.Slice.impl__len #u8 okm_future <: usize) =.
          (Core_models.Slice.impl__len #u8 okm <: usize))

unfold
let sha256 = sha256'
