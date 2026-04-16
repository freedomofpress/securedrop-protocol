module Securedrop_protocol_minimal.Wire.Setup
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Request from the newsroom to FPF for verification.
/// Step 2 in the spec.
type t_NewsroomSetupRequest = {
  f_newsroom_verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey
}

/// Response from FPF to the newsroom.
/// Step 2 in the spec.
type t_NewsroomSetupResponse = {
  f_sig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
}
