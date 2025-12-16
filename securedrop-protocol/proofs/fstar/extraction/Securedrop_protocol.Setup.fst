module Securedrop_protocol.Setup
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Setup a newsroom. This corresponds to step 2 in the spec.
/// This runs on FPF hardware.
/// The generated newsroom verifying key is sent to FPF,
/// which produces a signature over the newsroom verifying key using the
/// FPF signing key.
/// TODO: There is a manual verification step here, so the caller should
/// instruct the user to stop, verify the fingerprint out of band, and
/// then proceed. The caller should also persist the fingerprint and signature
/// in its local data store.
let impl__sign
      (self: Securedrop_protocol.Messages.Setup.t_NewsroomSetupRequest)
      (fpf_keys: Securedrop_protocol.Keys.t_FPFKeyPair)
    : Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_NewsroomSetupResponse
      Anyhow.t_Error =
  let newsroom_pk_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes self
        .Securedrop_protocol.Messages.Setup.f_newsroom_verifying_key
  in
  let sig:Securedrop_protocol.Sign.t_Signature =
    Securedrop_protocol.Sign.impl_SigningKey__sign fpf_keys.Securedrop_protocol.Keys.f_sk
      (newsroom_pk_bytes <: t_Slice u8)
  in
  Core_models.Result.Result_Ok
  ({ Securedrop_protocol.Messages.Setup.f_sig = sig }
    <:
    Securedrop_protocol.Messages.Setup.t_NewsroomSetupResponse)
  <:
  Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_NewsroomSetupResponse
    Anyhow.t_Error
