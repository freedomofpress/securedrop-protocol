module Securedrop_protocol_minimal.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Sign in
  ()

/// A key pair for FPF (Freedom of the Press Foundation).
type t_FPFKeyPair = {
  f_sk:Securedrop_protocol_minimal.Sign.t_SigningKey;
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey
}

/// Sign `msg` in domain `D` using the FPF signing key.
let impl_FPFKeyPair__sign
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Sign.t_DomainTag v_D)
      (self: t_FPFKeyPair)
      (msg: t_Slice u8)
    : Securedrop_protocol_minimal.Sign.t_Signature v_D =
  Securedrop_protocol_minimal.Sign.impl_SigningKey__sign #v_D self.f_sk msg
