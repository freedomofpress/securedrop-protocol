module Securedrop_protocol_minimal.Sign
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Sign.Private in
  ()

/// Marker trait for signature domain separation.
/// Each impl encodes the ASCII tag that is prepended to every signing preimage
/// in that domain: `len(tag) || tag || msg`  (see footnote in the spec).
class t_DomainTag (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:Securedrop_protocol_minimal.Sign.Private.t_Sealed
  v_Self;
  f_TAG:t_Slice u8
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_DomainTag v_Self|} -> i._super_i0

/// Journalist self-signature over long-term public keys (step 3.1).
type t_JournalistLongTermKey = | JournalistLongTermKey : t_JournalistLongTermKey

/// Journalist self-signature over ephemeral key bundles (step 3.2).
type t_JournalistEphemeralKey = | JournalistEphemeralKey : t_JournalistEphemeralKey

/// FPF signature over the newsroom's verifying key (step 2).
type t_FpfOnNewsroom = | FpfOnNewsroom : t_FpfOnNewsroom

/// An Ed25519 signature carrying its domain at the type level.
/// A `Signature<D>` can only be verified against a message using the same
/// domain `D`, making cross-domain misuse a compile error rather than a
/// runtime failure.
type t_Signature (v_D: Type0) {| i0: t_DomainTag v_D |} = {
  f_bytes:t_Array u8 (mk_usize 64);
  f_e_phantom:Core_models.Marker.t_PhantomData (Prims.unit -> v_D)
}

/// An Ed25519 verification key.
type t_VerifyingKey = | VerifyingKey : Libcrux_ed25519.Impl_hacl.t_VerificationKey -> t_VerifyingKey
