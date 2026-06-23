module Securedrop_protocol_minimal.Wire.Setup
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Request from the newsroom to FPF for verification.
/// Step 2 in the spec.
type t_NewsroomSetupRequest = {
  f_newsroom_verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl': Core_models.Fmt.t_Debug t_NewsroomSetupRequest

unfold
let impl = impl'

/// Response from FPF to the newsroom.
/// Step 2 in the spec.
type t_NewsroomSetupResponse = {
  f_sig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Fmt.t_Debug t_NewsroomSetupResponse

unfold
let impl_1 = impl_1'

/// Request from the journalist to the newsroom for initial onboarding.
/// Step 3.1 in the spec.
type t_JournalistSetupRequest = { f_enrollment:Securedrop_protocol_minimal.Keys.t_Enrollment }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Fmt.t_Debug t_JournalistSetupRequest

unfold
let impl_2 = impl_2'

/// Response from the newsroom to the journalist for initial onboarding.
/// Step 3.1 in the spec.
type t_JournalistSetupResponse = {
  f_sig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Fmt.t_Debug t_JournalistSetupResponse

unfold
let impl_3 = impl_3'

/// Request from the journalist to the SecureDrop server for ephemeral key replenishment.
/// Step 3.2 in the spec.
type t_JournalistEphemeralKeyRequest = {
  f_verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_bundles:Alloc.Vec.t_Vec
    (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
      Securedrop_protocol_minimal.Sign.t_Signature
      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Fmt.t_Debug t_JournalistEphemeralKeyRequest

unfold
let impl_4 = impl_4'
