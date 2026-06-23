module Securedrop_protocol_minimal.Primitives.Provider.Ed25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  ()

/// Generate an ed25519 keypair
assume
val keygen': #v_R: Type0 -> {| i0: Rand_core.t_CryptoRng v_R |} -> rng: v_R
  -> (v_R &
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 32))
        Anyhow.t_Error)

unfold
let keygen (#v_R: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_CryptoRng v_R) =
  keygen' #v_R #i0

/// Sign `payload` with Ed25519 secret key bytes.
assume
val sign': payload: t_Slice u8 -> private_key: t_Array u8 (mk_usize 32)
  -> Core_models.Result.t_Result (t_Array u8 (mk_usize 64)) Anyhow.t_Error

unfold
let sign = sign'

/// Verify an Ed25519 `signature` over `payload` with verifying key bytes.
assume
val verify':
    payload: t_Slice u8 ->
    public_key: t_Array u8 (mk_usize 32) ->
    signature: t_Array u8 (mk_usize 64)
  -> Core_models.Result.t_Result Prims.unit Anyhow.t_Error

unfold
let verify = verify'
