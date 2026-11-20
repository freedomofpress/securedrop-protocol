module Securedrop_protocol_minimal.Server.Setup
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Schemes.Sign in
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
      (fpf_keys: Securedrop_protocol_minimal.Keys.Fpf.t_FPFKeyPair)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupResponse
      Anyhow.t_Error =
  let newsroom_pk_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Schemes.Sign.impl_VerifyingKey__into_bytes self
        .Securedrop_protocol_minimal.Wire.Setup.f_newsroom_verifying_key
  in
  let
  (sig:
    Securedrop_protocol_minimal.Schemes.Sign.t_Signature
    Securedrop_protocol_minimal.Schemes.Sign.t_FpfOnNewsroom):Securedrop_protocol_minimal.Schemes.Sign.t_Signature
  Securedrop_protocol_minimal.Schemes.Sign.t_FpfOnNewsroom =
    Securedrop_protocol_minimal.Keys.Fpf.impl_FPFKeyPair__sign #Securedrop_protocol_minimal.Schemes.Sign.t_FpfOnNewsroom
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

/// Setup a journalist. This corresponds to step 3.1 in the spec.
/// The newsroom verifies the journalist's self-signature over their
/// long-term public keys, then signs the journalist's verifying key.
/// # Security
/// There is a manual verification step here, so the caller should
/// instruct the user to stop, verify the fingerprint out of band, and
/// then proceed. The caller should also persist the enrollment and
/// signature in its local data store.
/// TODO(later): How to handle signing when offline?
/// # Errors
/// Returns an error if the journalist's self-signature does not verify.
let impl_1__sign
      (self: Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest)
      (newsroom_keys: Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse
      Anyhow.t_Error =
  let vk_j:Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey =
    self.Securedrop_protocol_minimal.Wire.Setup.f_enrollment
      .Securedrop_protocol_minimal.Wire.Enrollment.f_verification_key
  in
  match
    Securedrop_protocol_minimal.Schemes.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Schemes.Sign.t_JournalistLongTermKey
      vk_j
      (Securedrop_protocol_minimal.Wire.Bundle.impl_SignedLongtermKeyBundle__bundle_bytes self
            .Securedrop_protocol_minimal.Wire.Setup.f_enrollment
            .Securedrop_protocol_minimal.Wire.Enrollment.f_bundle
        <:
        t_Slice u8)
      self.Securedrop_protocol_minimal.Wire.Setup.f_enrollment
        .Securedrop_protocol_minimal.Wire.Enrollment.f_bundle
        .Securedrop_protocol_minimal.Wire.Bundle.f_selfsig
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok _ ->
    let
    (sig:
      Securedrop_protocol_minimal.Schemes.Sign.t_Signature
      Securedrop_protocol_minimal.Schemes.Sign.t_NewsroomOnJournalist):Securedrop_protocol_minimal.Schemes.Sign.t_Signature
    Securedrop_protocol_minimal.Schemes.Sign.t_NewsroomOnJournalist =
      Securedrop_protocol_minimal.Keys.Newsroom.impl_NewsroomKeyPair__sign #Securedrop_protocol_minimal.Schemes.Sign.t_NewsroomOnJournalist
        newsroom_keys
        (Securedrop_protocol_minimal.Schemes.Sign.impl_VerifyingKey__into_bytes vk_j <: t_Slice u8)
    in
    Core_models.Result.Result_Ok
    ({ Securedrop_protocol_minimal.Wire.Setup.f_sig = sig }
      <:
      Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse
      Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse
      Anyhow.t_Error

/// Handle a journalist's ephemeral key replenishment request. This
/// corresponds to step 3.2 in the spec.
/// Each ephemeral key bundle must be signed by the journalist's
/// long-term signing key. The caller is responsible for checking that
/// the journalist is enrolled, and for storing the bundles.
/// # Errors
/// Returns an error if any bundle signature fails verification.
let impl_2__verify (self: Securedrop_protocol_minimal.Wire.Setup.t_JournalistEphemeralKeyRequest)
    : Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
  match
    Rust_primitives.Hax.Folds.fold_range_return (mk_usize 0)
      (Alloc.Vec.impl_1__len #(Securedrop_protocol_minimal.Keys.Bundle.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Schemes.Sign.t_Signature
            Securedrop_protocol_minimal.Schemes.Sign.t_JournalistEphemeralKey)
          #Alloc.Alloc.t_Global
          self.Securedrop_protocol_minimal.Wire.Setup.f_bundles
        <:
        usize)
      (fun temp_0_ temp_1_ ->
          let _:Prims.unit = temp_0_ in
          let _:usize = temp_1_ in
          true)
      ()
      (fun temp_0_ i ->
          let _:Prims.unit = temp_0_ in
          let i:usize = i in
          let signed_bundle:(Securedrop_protocol_minimal.Keys.Bundle.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Schemes.Sign.t_Signature
            Securedrop_protocol_minimal.Schemes.Sign.t_JournalistEphemeralKey) =
            self.Securedrop_protocol_minimal.Wire.Setup.f_bundles.[ i ]
          in
          match
            Securedrop_protocol_minimal.Schemes.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Schemes.Sign.t_JournalistEphemeralKey
              self.Securedrop_protocol_minimal.Wire.Setup.f_verifying_key
              (Alloc.Vec.impl_1__as_slice (Securedrop_protocol_minimal.Keys.Bundle.impl_KeyBundlePublic__as_bytes
                      signed_bundle._1
                    <:
                    Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                <:
                t_Slice u8)
              signed_bundle._2
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok _ ->
            Core_models.Ops.Control_flow.ControlFlow_Continue ()
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Result.t_Result Prims.unit Anyhow.t_Error) (Prims.unit & Prims.unit))
              Prims.unit
          | Core_models.Result.Result_Err err ->
            Core_models.Ops.Control_flow.ControlFlow_Break
            (Core_models.Ops.Control_flow.ControlFlow_Break
              (Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
              <:
              Core_models.Ops.Control_flow.t_ControlFlow
                (Core_models.Result.t_Result Prims.unit Anyhow.t_Error) (Prims.unit & Prims.unit))
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Result.t_Result Prims.unit Anyhow.t_Error) (Prims.unit & Prims.unit))
              Prims.unit)
    <:
    Core_models.Ops.Control_flow.t_ControlFlow
      (Core_models.Result.t_Result Prims.unit Anyhow.t_Error) Prims.unit
  with
  | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
  | Core_models.Ops.Control_flow.ControlFlow_Continue _ ->
    Core_models.Result.Result_Ok (() <: Prims.unit)
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
