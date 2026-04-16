module Securedrop_protocol_minimal.Keys.Newsroom
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol_minimal.Sign in
  ()

/// Newsroom keypair used for signing.
type t_NewsroomKeyPair = {
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_sk:Securedrop_protocol_minimal.Sign.t_SigningKey
}

let impl_NewsroomKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : Core_models.Result.t_Result t_NewsroomKeyPair Anyhow.t_Error =
  let
  (tmp0: v_R),
  (out: Core_models.Result.t_Result Securedrop_protocol_minimal.Sign.t_SigningKey Anyhow.t_Error) =
    Securedrop_protocol_minimal.Sign.impl_SigningKey__new #v_R rng
  in
  let rng:v_R = tmp0 in
  match
    out <: Core_models.Result.t_Result Securedrop_protocol_minimal.Sign.t_SigningKey Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok sk ->
    let vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
      sk.Securedrop_protocol_minimal.Sign.f_vk
    in
    Core_models.Result.Result_Ok ({ f_sk = sk; f_vk = vk } <: t_NewsroomKeyPair)
    <:
    Core_models.Result.t_Result t_NewsroomKeyPair Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result t_NewsroomKeyPair Anyhow.t_Error

/// Returns the verification key.
let impl_NewsroomKeyPair__verifying_key (self: t_NewsroomKeyPair)
    : Securedrop_protocol_minimal.Sign.t_VerifyingKey = self.f_vk

/// Sign `msg` in domain `D` using the newsroom signing key.
let impl_NewsroomKeyPair__sign
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Sign.t_DomainTag v_D)
      (self: t_NewsroomKeyPair)
      (msg: t_Slice u8)
    : Securedrop_protocol_minimal.Sign.t_Signature v_D =
  Securedrop_protocol_minimal.Sign.impl_SigningKey__sign #v_D self.f_sk msg
