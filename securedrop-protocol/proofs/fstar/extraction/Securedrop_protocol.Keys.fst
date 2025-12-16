module Securedrop_protocol.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  ()

/// A key pair for FPF.
/// TODO: Make the signing key private.
type t_FPFKeyPair = {
  f_sk:Securedrop_protocol.Sign.t_SigningKey;
  f_vk:Securedrop_protocol.Sign.t_VerifyingKey
}

let impl_FPFKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_FPFKeyPair =
  let
  (tmp0: v_R),
  (out: Core_models.Result.t_Result Securedrop_protocol.Sign.t_SigningKey Anyhow.t_Error) =
    Securedrop_protocol.Sign.impl_SigningKey__new #v_R rng
  in
  let rng:v_R = tmp0 in
  let sk:Securedrop_protocol.Sign.t_SigningKey =
    Core_models.Result.impl__unwrap #Securedrop_protocol.Sign.t_SigningKey #Anyhow.t_Error out
  in
  let vk:Securedrop_protocol.Sign.t_VerifyingKey = sk.Securedrop_protocol.Sign.f_vk in
  { f_sk = sk; f_vk = vk } <: t_FPFKeyPair
