module Securedrop_protocol_minimal.Setup
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Sign in
  ()

/// Setup a newsroom. This corresponds to step 2 in the spec.
/// This runs on FPF hardware.
/// The generated newsroom verifying key is sent to FPF,
/// which produces a signature over the newsroom verifying key using the
/// FPF signing key.
/// # Security
/// There is a manual verification step here: the caller should
/// instruct the user to stop, verify the fingerprint out of band, and
/// then proceed. The caller should also persist the fingerprint and signature
/// in its local data store.
let impl__sign
      (self: Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest)
      (fpf_keys: Securedrop_protocol_minimal.Keys.t_FPFKeyPair)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupResponse
      Anyhow.t_Error =
  let newsroom_pk_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Sign.impl_VerifyingKey__into_bytes self
        .Securedrop_protocol_minimal.Wire.Setup.f_newsroom_verifying_key
  in
  let
  (sig:
    Securedrop_protocol_minimal.Sign.t_Signature Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom):Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom =
    Securedrop_protocol_minimal.Keys.impl_FPFKeyPair__sign #Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
      fpf_keys
      (newsroom_pk_bytes <: t_Slice u8)
  in
  Core_models.Result.Result_Ok
  ({ Securedrop_protocol_minimal.Wire.Setup.f_sig = sig }
    <:
    Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupResponse)
  <:
  Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupResponse
    Anyhow.t_Error
