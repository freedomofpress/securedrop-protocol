module Securedrop_protocol.Messages.Setup
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Request from the newsroom to FPF for verification.
/// Step 2 in the spec.
type t_NewsroomSetupRequest = { f_newsroom_verifying_key:Securedrop_protocol.Sign.t_VerifyingKey }

/// Response from FPF to the newsroom.
/// Step 2 in the spec.
type t_NewsroomSetupResponse = { f_sig:Securedrop_protocol.Sign.t_Signature }

/// Request from the journalist to the newsroom for initial onboarding.
/// Step 3.1 in the spec.
type t_JournalistSetupRequest = {
  f_enrollment_key_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistEnrollmentKeyBundle
}

/// Response from the newsroom to the journalist for initial onboarding.
/// Step 3.1 in the spec.
type t_JournalistSetupResponse = { f_sig:Securedrop_protocol.Sign.t_Signature }

/// Request from the journalist to the SecureDrop server for ephemeral key replenishment.
/// Step 3.2 in the spec.
type t_JournalistRefreshRequest = {
  f_journalist_verifying_key:Securedrop_protocol.Sign.t_VerifyingKey;
  f_ephemeral_key_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
}

/// Response from the server to the journalist for ephemeral key replenishment.
/// Step 3.2 in the spec.
type t_JournalistRefreshResponse = { f_success:bool }
