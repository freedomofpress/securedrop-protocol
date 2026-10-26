module Securedrop_protocol_minimal.Wire.Bundle
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Schemes.Sign in
  ()

type t_SignedLongtermKeyBundle = {
  f_bundle:Securedrop_protocol_minimal.Keys.Bundle.t_LongtermKeyBundle;
  f_selfsig:Securedrop_protocol_minimal.Schemes.Sign.t_Signature
  Securedrop_protocol_minimal.Schemes.Sign.t_JournalistLongTermKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Fmt.t_Debug t_SignedLongtermKeyBundle

unfold
let impl_1 = impl_1'

let impl_2: Core_models.Clone.t_Clone t_SignedLongtermKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_SignedLongtermKeyBundle__new
      (bundle: Securedrop_protocol_minimal.Keys.Bundle.t_LongtermKeyBundle)
      (selfsig:
          Securedrop_protocol_minimal.Schemes.Sign.t_Signature
          Securedrop_protocol_minimal.Schemes.Sign.t_JournalistLongTermKey)
    : t_SignedLongtermKeyBundle =
  { f_bundle = bundle; f_selfsig = selfsig } <: t_SignedLongtermKeyBundle

let impl_SignedLongtermKeyBundle__as_bytes (self: t_SignedLongtermKeyBundle)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let bundle_bytes:t_Array u8 (mk_usize 1248) =
    Securedrop_protocol_minimal.Keys.Bundle.impl_LongtermKeyBundle__as_bytes self.f_bundle
  in
  let sig_bytes:t_Array u8 (mk_usize 64) =
    Securedrop_protocol_minimal.Schemes.Sign.impl_7__as_bytes #Securedrop_protocol_minimal.Schemes.Sign.t_JournalistLongTermKey
      self.f_selfsig
  in
  let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8
      ((Core_models.Slice.impl__len #u8 (bundle_bytes <: t_Slice u8) <: usize) +!
        (Core_models.Slice.impl__len #u8 (sig_bytes <: t_Slice u8) <: usize)
        <:
        usize)
  in
  let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      pubkey_bytes
      (bundle_bytes <: t_Slice u8)
  in
  let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      pubkey_bytes
      (sig_bytes <: t_Slice u8)
  in
  pubkey_bytes

let impl_SignedLongtermKeyBundle__bundle_bytes (self: t_SignedLongtermKeyBundle)
    : t_Array u8 (mk_usize 1248) =
  Securedrop_protocol_minimal.Keys.Bundle.impl_LongtermKeyBundle__as_bytes self.f_bundle

let impl_SignedLongtermKeyBundle__apke (self: t_SignedLongtermKeyBundle)
    : Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey =
  self.f_bundle.Securedrop_protocol_minimal.Keys.Bundle.f_apke

let impl_SignedLongtermKeyBundle__fetch_pk (self: t_SignedLongtermKeyBundle)
    : Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
  self.f_bundle.Securedrop_protocol_minimal.Keys.Bundle.f_fetch_pk
