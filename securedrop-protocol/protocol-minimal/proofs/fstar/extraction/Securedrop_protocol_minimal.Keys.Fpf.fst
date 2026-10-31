module Securedrop_protocol_minimal.Keys.Fpf
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol_minimal.Schemes.Sign in
  ()

/// A key pair for FPF (Freedom of the Press Foundation).
type t_FPFKeyPair = { f_sk:Securedrop_protocol_minimal.Schemes.Sign.t_SigningKey }

/// Generate a new FPF key pair.
/// # Errors
/// Returns an error if the key generation fails.
let impl_FPFKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Sign.t_SigningKey Anyhow.t_Error
  ) =
    Securedrop_protocol_minimal.Schemes.Sign.impl_SigningKey__new #v_R rng
  in
  let rng:v_R = tmp0 in
  match
    out
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Sign.t_SigningKey Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok sk ->
    let hax_temp_output:Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error =
      Core_models.Result.Result_Ok ({ f_sk = sk } <: t_FPFKeyPair)
      <:
      Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error
    in
    rng, hax_temp_output <: (v_R & Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error)

/// Returns the verification key.
let impl_FPFKeyPair__verifying_key (self: t_FPFKeyPair)
    : Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey =
  self.f_sk.Securedrop_protocol_minimal.Schemes.Sign.f_vk

/// Sign `msg` in domain `D` using the FPF signing key.
let impl_FPFKeyPair__sign
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Schemes.Sign.t_DomainTag v_D)
      (self: t_FPFKeyPair)
      (msg: t_Slice u8)
    : Securedrop_protocol_minimal.Schemes.Sign.t_Signature v_D =
  Securedrop_protocol_minimal.Schemes.Sign.impl_SigningKey__sign #v_D self.f_sk msg

/// The FPF signing key used as a secret.
let impl_FPFKeyPair__as_bytes (self: t_FPFKeyPair) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol_minimal.Schemes.Sign.impl_SigningKey__as_bytes self.f_sk

/// Reconstruct an [`FPFKeyPair`] from its secret.
let impl_FPFKeyPair__from_bytes (seed: t_Array u8 (mk_usize 32)) : t_FPFKeyPair =
  { f_sk = Securedrop_protocol_minimal.Schemes.Sign.impl_SigningKey__from_seed seed }
  <:
  t_FPFKeyPair
