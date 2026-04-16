module Securedrop_protocol_minimal.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Sign in
  ()

/// The public keys that make up one ephemeral key bundle
type t_KeyBundlePublic = {
  f_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_metadata_pk:Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
}

type t_SignedLongtermPubKeyBytes =
  | SignedLongtermPubKeyBytes : t_Array u8 (mk_usize 1248) -> t_SignedLongtermPubKeyBytes

type t_Enrollment = {
  f_bundle:t_SignedLongtermPubKeyBytes;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey;
  f_keys:(Securedrop_protocol_minimal.Sign.t_VerifyingKey &
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
    Securedrop_protocol_minimal.Message.t_MessagePublicKey)
}

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
