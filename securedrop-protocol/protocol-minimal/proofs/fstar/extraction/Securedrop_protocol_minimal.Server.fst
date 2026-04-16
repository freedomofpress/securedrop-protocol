module Securedrop_protocol_minimal.Server
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Ahash in
  let open Ahash.Fallback_hash in
  let open Allocator_api2.Stable.Alloc in
  let open Allocator_api2.Stable.Alloc.Global in
  let open Hashbrown in
  let open Rand_core in
  let open Securedrop_protocol_minimal.Ciphertext in
  let open Securedrop_protocol_minimal.Sign in
  let open Uuid in
  ()

/// Server session for handling source requests
type t_Server = {
  f_storage:Securedrop_protocol_minimal.Storage.t_ServerStorage;
  f_newsroom_keys:Core_models.Option.t_Option
  Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair;
  f_signature:Core_models.Option.t_Option
  (Securedrop_protocol_minimal.Sign.t_Signature Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Default.t_Default t_Server

unfold
let impl_1 = impl_1'

/// Create a new server session
/// TODO: Load newsroom keys from storage if they exist.
let impl_Server__new (_: Prims.unit) : t_Server =
  Core_models.Default.f_default #t_Server #FStar.Tactics.Typeclasses.solve ()

/// Generate a new newsroom setup request.
/// This creates a newsroom key pair, stores it in the server storage,
/// and returns a setup request that can be sent to FPF for signing.
/// TODO: The caller should persist these keys to disk.
let impl_Server__create_newsroom_setup_request
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_Server)
      (rng: v_R)
    : (t_Server &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest
        Anyhow.t_Error) =
  match
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol_minimal::keys::newsroom::impl_NewsroomKeyPair__new::<\n &mut R,\n >(&mut (rng))"

    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
      Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok newsroom_keys ->
    let newsroom_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
      Securedrop_protocol_minimal.Keys.Newsroom.impl_NewsroomKeyPair__verifying_key newsroom_keys
    in
    let self:t_Server =
      {
        self with
        f_newsroom_keys
        =
        Core_models.Option.Option_Some newsroom_keys
        <:
        Core_models.Option.t_Option Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
      }
      <:
      t_Server
    in
    let hax_temp_output:Core_models.Result.t_Result
      Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest Anyhow.t_Error =
      Core_models.Result.Result_Ok
      ({ Securedrop_protocol_minimal.Wire.Setup.f_newsroom_verifying_key = newsroom_vk }
        <:
        Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest)
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest
        Anyhow.t_Error
    in
    self, hax_temp_output
    <:
    (t_Server &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest
        Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest
        Anyhow.t_Error)
    <:
    (t_Server &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_NewsroomSetupRequest
        Anyhow.t_Error)

/// Setup a journalist. This corresponds to step 3.1 in the spec.
/// The newsroom then signs the bundle of journalist public keys.
/// TODO: There is a manual verification step here, so the caller should
/// instruct the user to stop, verify the fingerprint out of band, and
/// then proceed. The caller should also persist the fingerprint and signature
/// in its local data store.
/// TODO(later): How to handle signing when offline? (Not relevant for benchmarking)
let impl_Server__setup_journalist
      (self: t_Server)
      (request: Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest)
    : (t_Server &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse
        Anyhow.t_Error) =
  let journalist_signing_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
    request.Securedrop_protocol_minimal.Wire.Setup.f_enrollment
      .Securedrop_protocol_minimal.Keys.f_keys
      ._1
  in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Anyhow.t_Error
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey
          journalist_signing_key
          (Securedrop_protocol_minimal.Keys.impl_SignedLongtermPubKeyBytes__as_bytes request
                .Securedrop_protocol_minimal.Wire.Setup.f_enrollment
                .Securedrop_protocol_minimal.Keys.f_bundle
            <:
            t_Slice u8)
          request.Securedrop_protocol_minimal.Wire.Setup.f_enrollment
            .Securedrop_protocol_minimal.Keys.f_selfsig
        <:
        Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
      (fun temp_0_ ->
          let _:Anyhow.t_Error = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["Invalid signature on longterm keys"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok _ ->
    let verifying_key_bytes:t_Array u8 (mk_usize 32) =
      Securedrop_protocol_minimal.Sign.impl_VerifyingKey__into_bytes request
          .Securedrop_protocol_minimal.Wire.Setup.f_enrollment
          .Securedrop_protocol_minimal.Keys.f_keys
          ._1
    in
    (match
        Core_models.Option.impl__ok_or_else #Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
          #Anyhow.t_Error
          (Core_models.Option.impl__as_ref #Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
              self.f_newsroom_keys
            <:
            Core_models.Option.t_Option Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair)
          (fun temp_0_ ->
              let _:Prims.unit = temp_0_ in
              let error:Anyhow.t_Error =
                Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                      (let list = ["Newsroom keys not found in session"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                    <:
                    Core_models.Fmt.t_Arguments)
              in
              Anyhow.__private.must_use error)
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
          Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok newsroom_keys ->
        let
        (newsroom_signature:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist):Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist =
          Securedrop_protocol_minimal.Keys.Newsroom.impl_NewsroomKeyPair__sign #Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist
            newsroom_keys
            (verifying_key_bytes <: t_Slice u8)
        in
        let (tmp0: Securedrop_protocol_minimal.Storage.t_ServerStorage), (out: Uuid.t_Uuid) =
          Securedrop_protocol_minimal.Storage.impl_ServerStorage__add_journalist self.f_storage
            request.Securedrop_protocol_minimal.Wire.Setup.f_enrollment
            (Core_models.Clone.f_clone #(Securedrop_protocol_minimal.Sign.t_Signature
                  Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist)
                #FStar.Tactics.Typeclasses.solve
                newsroom_signature
              <:
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist)
        in
        let self:t_Server = { self with f_storage = tmp0 } <: t_Server in
        let e_journalist_id:Uuid.t_Uuid = out in
        let hax_temp_output:Core_models.Result.t_Result
          Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse Anyhow.t_Error =
          Core_models.Result.Result_Ok
          ({ Securedrop_protocol_minimal.Wire.Setup.f_sig = newsroom_signature }
            <:
            Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse)
          <:
          Core_models.Result.t_Result
            Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse Anyhow.t_Error
        in
        self, hax_temp_output
        <:
        (t_Server &
          Core_models.Result.t_Result
            Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        self,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result
            Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse Anyhow.t_Error)
        <:
        (t_Server &
          Core_models.Result.t_Result
            Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse
        Anyhow.t_Error)
    <:
    (t_Server &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupResponse
        Anyhow.t_Error)

/// Handle journalist ephemeral key replenishment. This corresponds to step 3.2 in the spec.
/// The journalist sends ephemeral keys signed by their signing key, and the server
/// verifies the signature and stores the ephemeral keys.
/// # Errors
/// Returns an error if the journalist is not found in storage, or if any bundle
/// signature fails verification.
let impl_Server__handle_ephemeral_key_request
      (self: t_Server)
      (request: Securedrop_protocol_minimal.Wire.Setup.t_JournalistEphemeralKeyRequest)
    : (t_Server & Core_models.Result.t_Result Prims.unit Anyhow.t_Error) =
  match
    Core_models.Option.impl__ok_or_else #Uuid.t_Uuid
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Storage.impl_ServerStorage__find_journalist_by_verifying_key self
            .f_storage
          request.Securedrop_protocol_minimal.Wire.Setup.f_verifying_key
        <:
        Core_models.Option.t_Option Uuid.t_Uuid)
      (fun temp_0_ ->
          let _:Prims.unit = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["Journalist not found in storage"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Uuid.t_Uuid Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok journalist_id ->
    let
    (_:
      Core_models.Slice.Iter.t_Iter
      (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
        Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)),
    (out: Core_models.Result.t_Result Prims.unit Anyhow.t_Error) =
      Core_models.Iter.Traits.Iterator.f_try_for_each #(Core_models.Slice.Iter.t_Iter
          (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))
        #FStar.Tactics.Typeclasses.solve
        #(Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
        (Core_models.Slice.impl__iter #(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
            (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                    (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                      Securedrop_protocol_minimal.Sign.t_Signature
                      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
                    Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                request.Securedrop_protocol_minimal.Wire.Setup.f_bundles
              <:
              t_Slice
              (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))
          <:
          Core_models.Slice.Iter.t_Iter
          (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))
        (fun k ->
            let k:(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) =
              k
            in
            Securedrop_protocol_minimal.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey
              request.Securedrop_protocol_minimal.Wire.Setup.f_verifying_key
              (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  (Securedrop_protocol_minimal.Keys.impl_KeyBundlePublic__as_bytes k._1
                    <:
                    Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                <:
                t_Slice u8)
              k._2
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
    in
    (match
        Core_models.Result.impl__map_err #Prims.unit
          #Anyhow.t_Error
          #Anyhow.t_Error
          out
          (fun temp_0_ ->
              let _:Anyhow.t_Error = temp_0_ in
              let error:Anyhow.t_Error =
                Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                      (let list = ["Invalid signature on ephemeral keys"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                    <:
                    Core_models.Fmt.t_Arguments)
              in
              Anyhow.__private.must_use error)
        <:
        Core_models.Result.t_Result Prims.unit Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok _ ->
        let self:t_Server =
          {
            self with
            f_storage
            =
            Securedrop_protocol_minimal.Storage.impl_ServerStorage__add_ephemeral_keys self
                .f_storage
              journalist_id
              request.Securedrop_protocol_minimal.Wire.Setup.f_bundles
          }
          <:
          t_Server
        in
        let hax_temp_output:Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
          Core_models.Result.Result_Ok (() <: Prims.unit)
          <:
          Core_models.Result.t_Result Prims.unit Anyhow.t_Error
        in
        self, hax_temp_output <: (t_Server & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        self,
        (Core_models.Result.Result_Err err <: Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
        <:
        (t_Server & Core_models.Result.t_Result Prims.unit Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err <: Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
    <:
    (t_Server & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)

/// Returns the newsroom verifying key, if one has been generated.
let impl_Server__newsroom_verifying_key (self: t_Server)
    : Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey =
  Core_models.Option.impl__map #Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
    #Securedrop_protocol_minimal.Sign.t_VerifyingKey
    (Core_models.Option.impl__as_ref #Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
        self.f_newsroom_keys
      <:
      Core_models.Option.t_Option Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair)
    (fun keys ->
        let keys:Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair = keys in
        Securedrop_protocol_minimal.Keys.Newsroom.impl_NewsroomKeyPair__verifying_key keys
        <:
        Securedrop_protocol_minimal.Sign.t_VerifyingKey)

/// Set the FPF signature for the newsroom
let impl_Server__set_fpf_signature
      (self: t_Server)
      (signature:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
    : t_Server =
  let self:t_Server =
    {
      self with
      f_signature
      =
      Core_models.Option.Option_Some signature
      <:
      Core_models.Option.t_Option
      (Securedrop_protocol_minimal.Sign.t_Signature Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
      )
    }
    <:
    t_Server
  in
  self

/// Get the ephemeral key count for a journalist
let impl_Server__ephemeral_keys_count (self: t_Server) (journalist_id: Uuid.t_Uuid) : usize =
  Securedrop_protocol_minimal.Storage.impl_ServerStorage__ephemeral_keys_count self.f_storage
    journalist_id

/// Check if a journalist has ephemeral keys available
let impl_Server__has_ephemeral_keys (self: t_Server) (journalist_id: Uuid.t_Uuid) : bool =
  Securedrop_protocol_minimal.Storage.impl_ServerStorage__has_ephemeral_keys self.f_storage
    journalist_id

/// Find journalist ID by verifying key
let impl_Server__find_journalist_id
      (self: t_Server)
      (verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
    : Core_models.Option.t_Option Uuid.t_Uuid =
  Securedrop_protocol_minimal.Storage.impl_ServerStorage__find_journalist_by_verifying_key self
      .f_storage
    verifying_key

/// Check if a message exists with the given ID
let impl_Server__has_message (self: t_Server) (message_id: Uuid.t_Uuid) : bool =
  Hashbrown.Map.impl_5__contains_key #Uuid.t_Uuid
    #Securedrop_protocol_minimal.Ciphertext.t_Envelope
    #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    #Allocator_api2.Stable.Alloc.Global.t_Global
    #Uuid.t_Uuid
    (Securedrop_protocol_minimal.Storage.impl_ServerStorage__get_messages self.f_storage
      <:
      Hashbrown.Map.t_HashMap Uuid.t_Uuid
        Securedrop_protocol_minimal.Ciphertext.t_Envelope
        (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
        Allocator_api2.Stable.Alloc.Global.t_Global)
    message_id

/// Handle source newsroom key request (step 5)
let impl_Server__handle_source_newsroom_key_request
      (self: t_Server)
      (e_request: Securedrop_protocol_minimal.Wire.Core.t_SourceNewsroomKeyRequest)
    : Securedrop_protocol_minimal.Wire.Core.t_SourceNewsroomKeyResponse =
  {
    Securedrop_protocol_minimal.Wire.Core.f_newsroom_verifying_key
    =
    Securedrop_protocol_minimal.Keys.Newsroom.impl_NewsroomKeyPair__verifying_key (Core_models.Option.impl__expect
          #Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
          (Core_models.Option.impl__as_ref #Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair
              self.f_newsroom_keys
            <:
            Core_models.Option.t_Option Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair)
          "Newsroom keys not found"
        <:
        Securedrop_protocol_minimal.Keys.Newsroom.t_NewsroomKeyPair);
    Securedrop_protocol_minimal.Wire.Core.f_fpf_sig
    =
    Core_models.Clone.f_clone #(Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
      #FStar.Tactics.Typeclasses.solve
      (Core_models.Option.impl__expect #(Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
          (Core_models.Option.impl__as_ref #(Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
              self.f_signature
            <:
            Core_models.Option.t_Option
            (Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom))
          "FPF signature not found"
        <:
        Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
  }
  <:
  Securedrop_protocol_minimal.Wire.Core.t_SourceNewsroomKeyResponse

/// Handle source journalist key request (step 5)
let impl_Server__handle_source_journalist_key_request
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_Server)
      (e_request: Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyRequest)
      (rng: v_R)
    : (t_Server & v_R &
      Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse
        Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse ()
  in
  let
  (tmp0: Securedrop_protocol_minimal.Storage.t_ServerStorage),
  (tmp1: v_R),
  (out:
    Alloc.Vec.t_Vec
      (Uuid.t_Uuid &
        (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)) Alloc.Alloc.t_Global) =
    Securedrop_protocol_minimal.Storage.impl_ServerStorage__get_all_ephemeral_keys #v_R
      self.f_storage
      rng
  in
  let self:t_Server = { self with f_storage = tmp0 } <: t_Server in
  let rng:v_R = tmp1 in
  let journalist_ephemeral_keys:Alloc.Vec.t_Vec
    (Uuid.t_Uuid &
      (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
        Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)) Alloc.Alloc.t_Global =
    out
  in
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse
    Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
              (Uuid.t_Uuid &
                (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                  Securedrop_protocol_minimal.Sign.t_Signature
                  Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)) Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          journalist_ephemeral_keys
        <:
        Alloc.Vec.Into_iter.t_IntoIter
          (Uuid.t_Uuid &
            (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)) Alloc.Alloc.t_Global)
      responses
      (fun responses temp_1_ ->
          let responses:Alloc.Vec.t_Vec
            Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse Alloc.Alloc.t_Global
          =
            responses
          in
          let
          (journalist_id: Uuid.t_Uuid),
          (ephemeral_bundle:
            (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)) =
            temp_1_
          in
          let
          (signing_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey),
          (fetching_key: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey),
          (reply_apke_pk: Securedrop_protocol_minimal.Message.t_MessagePublicKey),
          (journalist_self_sig:
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey),
          (signed_pubkey_bytes: Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes),
          (newsroom_sig:
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist) =
            Core_models.Clone.f_clone #(Securedrop_protocol_minimal.Sign.t_VerifyingKey &
                Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
                Securedrop_protocol_minimal.Message.t_MessagePublicKey &
                Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey &
                Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes &
                Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist)
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__expect #(Securedrop_protocol_minimal.Sign.t_VerifyingKey &
                    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
                    Securedrop_protocol_minimal.Message.t_MessagePublicKey &
                    Securedrop_protocol_minimal.Sign.t_Signature
                    Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey &
                    Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes &
                    Securedrop_protocol_minimal.Sign.t_Signature
                    Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist)
                  (Hashbrown.Map.impl_5__get #Uuid.t_Uuid
                      #(Securedrop_protocol_minimal.Sign.t_VerifyingKey &
                        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
                        Securedrop_protocol_minimal.Message.t_MessagePublicKey &
                        Securedrop_protocol_minimal.Sign.t_Signature
                        Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey &
                        Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes &
                        Securedrop_protocol_minimal.Sign.t_Signature
                        Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist)
                      #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
                      #Allocator_api2.Stable.Alloc.Global.t_Global
                      #Uuid.t_Uuid
                      (Securedrop_protocol_minimal.Storage.impl_ServerStorage__get_journalists self
                            .f_storage
                        <:
                        Hashbrown.Map.t_HashMap Uuid.t_Uuid
                          (Securedrop_protocol_minimal.Sign.t_VerifyingKey &
                            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
                            Securedrop_protocol_minimal.Message.t_MessagePublicKey &
                            Securedrop_protocol_minimal.Sign.t_Signature
                            Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey &
                            Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes &
                            Securedrop_protocol_minimal.Sign.t_Signature
                            Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist)
                          (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
                          Allocator_api2.Stable.Alloc.Global.t_Global)
                      journalist_id
                    <:
                    Core_models.Option.t_Option
                    (Securedrop_protocol_minimal.Sign.t_VerifyingKey &
                      Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
                      Securedrop_protocol_minimal.Message.t_MessagePublicKey &
                      Securedrop_protocol_minimal.Sign.t_Signature
                      Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey &
                      Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes &
                      Securedrop_protocol_minimal.Sign.t_Signature
                      Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist))
                  "Journalist should exist in storage"
                <:
                (Securedrop_protocol_minimal.Sign.t_VerifyingKey &
                  Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
                  Securedrop_protocol_minimal.Message.t_MessagePublicKey &
                  Securedrop_protocol_minimal.Sign.t_Signature
                  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey &
                  Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes &
                  Securedrop_protocol_minimal.Sign.t_Signature
                  Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist))
          in
          let journo_public:Securedrop_protocol_minimal.Journalist.t_JournalistPublicView =
            Securedrop_protocol_minimal.Journalist.impl_JournalistPublicView__new signing_key
              fetching_key
              reply_apke_pk
              journalist_self_sig
              signed_pubkey_bytes
              ephemeral_bundle
          in
          let response:Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse =
            {
              Securedrop_protocol_minimal.Wire.Core.f_journalist = journo_public;
              Securedrop_protocol_minimal.Wire.Core.f_nr_signature = newsroom_sig
            }
            <:
            Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse
          in
          let responses:Alloc.Vec.t_Vec
            Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse Alloc.Alloc.t_Global
          =
            Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse
              #Alloc.Alloc.t_Global
              responses
              response
          in
          responses)
  in
  let hax_temp_output:Alloc.Vec.t_Vec
    Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse Alloc.Alloc.t_Global =
    responses
  in
  self, rng, hax_temp_output
  <:
  (t_Server & v_R &
    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_SourceJournalistKeyResponse
      Alloc.Alloc.t_Global)

/// Handle message submission (step 6 for sources, step 9 for journalists)
let impl_Server__handle_message_submit
      (self: t_Server)
      (message: Securedrop_protocol_minimal.Ciphertext.t_Envelope)
    : (t_Server & Core_models.Result.t_Result Uuid.t_Uuid Anyhow.t_Error) =
  let message_id:Uuid.t_Uuid = Uuid.V4.impl__new_v4 () in
  let self:t_Server =
    {
      self with
      f_storage
      =
      Securedrop_protocol_minimal.Storage.impl_ServerStorage__add_message self.f_storage
        message_id
        message
    }
    <:
    t_Server
  in
  let hax_temp_output:Core_models.Result.t_Result Uuid.t_Uuid Anyhow.t_Error =
    Core_models.Result.Result_Ok message_id
    <:
    Core_models.Result.t_Result Uuid.t_Uuid Anyhow.t_Error
  in
  self, hax_temp_output <: (t_Server & Core_models.Result.t_Result Uuid.t_Uuid Anyhow.t_Error)

/// Compute "hints"/challenges for message id fetch request (step 7)
let impl_Server__handle_request_challenges
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_Server)
      (e_request: Securedrop_protocol_minimal.Wire.Core.t_MessageChallengeFetchRequest)
      (rng: v_R)
    : (v_R &
      Core_models.Result.t_Result
        Securedrop_protocol_minimal.Wire.Core.t_MessageChallengeFetchResponse Anyhow.t_Error) =
  let (total_challenges: usize):usize =
    Securedrop_protocol_minimal.Primitives.v_MESSAGE_ID_FETCH_SIZE
  in
  let store:Hashbrown.Map.t_HashMap Uuid.t_Uuid
    Securedrop_protocol_minimal.Ciphertext.t_Envelope
    (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    Allocator_api2.Stable.Alloc.Global.t_Global =
    Securedrop_protocol_minimal.Storage.impl_ServerStorage__get_messages self.f_storage
  in
  let
  (tmp0: v_R),
  (out: Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global)
  =
    Securedrop_protocol_minimal.Encrypt_decrypt.compute_fetch_challenges #v_R
      rng
      store
      total_challenges
  in
  let rng:v_R = tmp0 in
  let chall:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global =
    out
  in
  let hax_temp_output:Core_models.Result.t_Result
    Securedrop_protocol_minimal.Wire.Core.t_MessageChallengeFetchResponse Anyhow.t_Error =
    Core_models.Result.Result_Ok
    ({
        Securedrop_protocol_minimal.Wire.Core.f_count = total_challenges;
        Securedrop_protocol_minimal.Wire.Core.f_messages = chall
      }
      <:
      Securedrop_protocol_minimal.Wire.Core.t_MessageChallengeFetchResponse)
    <:
    Core_models.Result.t_Result
      Securedrop_protocol_minimal.Wire.Core.t_MessageChallengeFetchResponse Anyhow.t_Error
  in
  rng, hax_temp_output
  <:
  (v_R &
    Core_models.Result.t_Result
      Securedrop_protocol_minimal.Wire.Core.t_MessageChallengeFetchResponse Anyhow.t_Error)

/// Handle message ID fetch request (step 7)
/// TODO: Nothing here prevents someone from requesting messages
/// that aren't theirs? Should request messages have a signature?
/// Handle message fetch request (step 8/10)
let impl_Server__handle_message_fetch
      (self: t_Server)
      (request: Securedrop_protocol_minimal.Wire.Core.t_MessageFetchRequest)
    : Core_models.Option.t_Option Securedrop_protocol_minimal.Ciphertext.t_Envelope =
  Core_models.Option.impl_2__cloned #Securedrop_protocol_minimal.Ciphertext.t_Envelope
    (Hashbrown.Map.impl_5__get #Uuid.t_Uuid
        #Securedrop_protocol_minimal.Ciphertext.t_Envelope
        #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
        #Allocator_api2.Stable.Alloc.Global.t_Global
        #Uuid.t_Uuid
        (Securedrop_protocol_minimal.Storage.impl_ServerStorage__get_messages self.f_storage
          <:
          Hashbrown.Map.t_HashMap Uuid.t_Uuid
            Securedrop_protocol_minimal.Ciphertext.t_Envelope
            (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
            Allocator_api2.Stable.Alloc.Global.t_Global)
        request.Securedrop_protocol_minimal.Wire.Core.f_message_id
      <:
      Core_models.Option.t_Option Securedrop_protocol_minimal.Ciphertext.t_Envelope)
