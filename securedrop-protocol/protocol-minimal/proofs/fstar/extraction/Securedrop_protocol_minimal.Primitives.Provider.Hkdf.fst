module Securedrop_protocol_minimal.Primitives.Provider.Hkdf
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// HKDF-SHA256
assume
val sha256': okm: t_Slice u8 -> salt: t_Slice u8 -> ikm: t_Slice u8 -> info: t_Slice u8
  -> Prims.Pure (t_Slice u8 & Core_models.Result.t_Result Prims.unit Libcrux_hkdf.t_ExpandError)
      (requires
        (Core_models.Slice.impl__len #u8 okm <: usize) <=. (mk_usize 255 *! mk_usize 32 <: usize) &&
        (Core_models.Slice.impl__len #u8 salt <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize) &&
        (Core_models.Slice.impl__len #u8 ikm <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize) &&
        (Core_models.Slice.impl__len #u8 info <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize))
      (ensures
        fun temp_0_ ->
          let
          (okm_future: t_Slice u8),
          (result: Core_models.Result.t_Result Prims.unit Libcrux_hkdf.t_ExpandError) =
            temp_0_
          in
          Core_models.Result.impl__is_ok #Prims.unit #Libcrux_hkdf.t_ExpandError result &&
          (Core_models.Slice.impl__len #u8 okm_future <: usize) =.
          (Core_models.Slice.impl__len #u8 okm <: usize))

unfold
let sha256 = sha256'
