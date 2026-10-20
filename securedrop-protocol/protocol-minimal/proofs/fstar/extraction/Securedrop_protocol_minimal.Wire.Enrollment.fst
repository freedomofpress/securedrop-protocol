module Securedrop_protocol_minimal.Wire.Enrollment
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_Enrollment = {
  f_bundle:Securedrop_protocol_minimal.Wire.Bundle.t_SignedLongtermKeyBundle;
  f_verification_key:Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey
}

let impl: Core_models.Clone.t_Clone t_Enrollment =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Fmt.t_Debug t_Enrollment

unfold
let impl_1 = impl_1'
