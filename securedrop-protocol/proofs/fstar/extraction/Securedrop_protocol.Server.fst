module Securedrop_protocol.Server
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
  let open Anyhow.Error in
  let open Hashbrown in
  let open Hashbrown.Map in
  let open Rand_core in
  let open Securedrop_protocol.Keys.Journalist in
  let open Securedrop_protocol.Sign in
  let open Uuid in
  ()

/// Server session for handling source requests
type t_Server = {
  f_storage:Securedrop_protocol.Storage.t_ServerStorage;
  f_newsroom_keys:Core_models.Option.t_Option Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair;
  f_signature:Core_models.Option.t_Option Securedrop_protocol.Sign.t_Signature
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
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_NewsroomSetupRequest
        Anyhow.t_Error) =
  let newsroom_keys:Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::newsroom::impl_NewsroomKeyPair__new::<&mut R>(&mut (rng))"
  in
  let newsroom_vk:Securedrop_protocol.Sign.t_VerifyingKey =
    newsroom_keys.Securedrop_protocol.Keys.Newsroom.f_vk
  in
  let self:t_Server =
    {
      self with
      f_newsroom_keys
      =
      Core_models.Option.Option_Some newsroom_keys
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
    }
    <:
    t_Server
  in
  let hax_temp_output:Core_models.Result.t_Result
    Securedrop_protocol.Messages.Setup.t_NewsroomSetupRequest Anyhow.t_Error =
    Core_models.Result.Result_Ok
    ({ Securedrop_protocol.Messages.Setup.f_newsroom_verifying_key = newsroom_vk }
      <:
      Securedrop_protocol.Messages.Setup.t_NewsroomSetupRequest)
    <:
    Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_NewsroomSetupRequest
      Anyhow.t_Error
  in
  self, hax_temp_output
  <:
  (t_Server &
    Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_NewsroomSetupRequest
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
      (request: Securedrop_protocol.Messages.Setup.t_JournalistSetupRequest)
    : (t_Server &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
        Anyhow.t_Error) =
  let enrollment_key_bundle_bytes:t_Array u8 (mk_usize 64) =
    Securedrop_protocol.Keys.Journalist.impl_JournalistLongtermPublicKeys__into_bytes (Core_models.Clone.f_clone
          #Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys
          #FStar.Tactics.Typeclasses.solve
          request.Securedrop_protocol.Messages.Setup.f_enrollment_key_bundle
            .Securedrop_protocol.Keys.Journalist.f_public_keys
        <:
        Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys)
  in
  let enrollment_self_signature:Securedrop_protocol.Sign.t_Signature =
    Securedrop_protocol.Sign.impl_SelfSignature__as_signature (Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_SelfSignature
          #FStar.Tactics.Typeclasses.solve
          request.Securedrop_protocol.Messages.Setup.f_enrollment_key_bundle
            .Securedrop_protocol.Keys.Journalist.f_self_signature
        <:
        Securedrop_protocol.Sign.t_SelfSignature)
  in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Anyhow.t_Error
      #Anyhow.t_Error
      (Securedrop_protocol.Sign.impl_VerifyingKey__verify request
            .Securedrop_protocol.Messages.Setup.f_enrollment_key_bundle
            .Securedrop_protocol.Keys.Journalist.f_signing_key
          (enrollment_key_bundle_bytes <: t_Slice u8)
          enrollment_self_signature
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
      Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes request
          .Securedrop_protocol.Messages.Setup.f_enrollment_key_bundle
          .Securedrop_protocol.Keys.Journalist.f_signing_key
    in
    (match
        Core_models.Option.impl__ok_or_else #Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
          #Anyhow.t_Error
          (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
              self.f_newsroom_keys
            <:
            Core_models.Option.t_Option Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair)
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
        Core_models.Result.t_Result Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
          Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok newsroom_keys ->
        let newsroom_signature:Securedrop_protocol.Sign.t_Signature =
          Securedrop_protocol.Sign.impl_SigningKey__sign newsroom_keys
              .Securedrop_protocol.Keys.Newsroom.f_sk
            (verifying_key_bytes <: t_Slice u8)
        in
        let (tmp0: Securedrop_protocol.Storage.t_ServerStorage), (out: Uuid.t_Uuid) =
          Securedrop_protocol.Storage.impl_ServerStorage__add_journalist self.f_storage
            request.Securedrop_protocol.Messages.Setup.f_enrollment_key_bundle
            (Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_Signature
                #FStar.Tactics.Typeclasses.solve
                newsroom_signature
              <:
              Securedrop_protocol.Sign.t_Signature)
        in
        let self:t_Server = { self with f_storage = tmp0 } <: t_Server in
        let e_journalist_id:Uuid.t_Uuid = out in
        let hax_temp_output:Core_models.Result.t_Result
          Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse Anyhow.t_Error =
          Core_models.Result.Result_Ok
          ({ Securedrop_protocol.Messages.Setup.f_sig = newsroom_signature }
            <:
            Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse)
          <:
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
            Anyhow.t_Error
        in
        self, hax_temp_output
        <:
        (t_Server &
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
            Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        self,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
            Anyhow.t_Error)
        <:
        (t_Server &
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
            Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
        Anyhow.t_Error)
    <:
    (t_Server &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupResponse
        Anyhow.t_Error)

/// Handle journalist ephemeral key replenishment. This corresponds to step 3.2 in the spec.
/// The journalist sends ephemeral keys signed by their signing key, and the server
/// verifies the signature and stores the ephemeral keys.
let impl_Server__handle_ephemeral_key_request
      (self: t_Server)
      (request: Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest)
    : (t_Server &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
        Anyhow.t_Error) =
  let bundle:Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle =
    request.Securedrop_protocol.Messages.Setup.f_ephemeral_key_bundle
  in
  let ephemeral_public_keys:Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys =
    bundle.Securedrop_protocol.Keys.Journalist.f_public_keys
  in
  let signed_message:t_Array u8 (mk_usize 2432) =
    Securedrop_protocol.Keys.Journalist.impl_JournalistOneTimePublicKeys__into_bytes (Core_models.Clone.f_clone
          #Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys
          #FStar.Tactics.Typeclasses.solve
          ephemeral_public_keys
        <:
        Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys)
  in
  match
    Core_models.Option.impl__ok_or_else #Uuid.t_Uuid
      #Anyhow.t_Error
      (Securedrop_protocol.Storage.impl_ServerStorage__find_journalist_by_verifying_key self
            .f_storage
          request.Securedrop_protocol.Messages.Setup.f_journalist_verifying_key
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
    (match
        Core_models.Result.impl__map_err #Prims.unit
          #Anyhow.t_Error
          #Anyhow.t_Error
          (Securedrop_protocol.Sign.impl_VerifyingKey__verify request
                .Securedrop_protocol.Messages.Setup.f_journalist_verifying_key
              (signed_message <: t_Slice u8)
              bundle.Securedrop_protocol.Keys.Journalist.f_signature
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
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
            Securedrop_protocol.Storage.impl_ServerStorage__add_ephemeral_keys self.f_storage
              journalist_id
              (Core_models.Convert.f_from #(Alloc.Vec.t_Vec
                      Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                      Alloc.Alloc.t_Global)
                  #(t_Array Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                      (mk_usize 1))
                  #FStar.Tactics.Typeclasses.solve
                  (let list = [bundle] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                  Alloc.Alloc.t_Global)
          }
          <:
          t_Server
        in
        let hax_temp_output:Core_models.Result.t_Result
          Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse Anyhow.t_Error =
          Core_models.Result.Result_Ok
          ({ Securedrop_protocol.Messages.Setup.f_success = true }
            <:
            Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse)
          <:
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
            Anyhow.t_Error
        in
        self, hax_temp_output
        <:
        (t_Server &
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
            Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        self,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
            Anyhow.t_Error)
        <:
        (t_Server &
          Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
            Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
        Anyhow.t_Error)
    <:
    (t_Server &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshResponse
        Anyhow.t_Error)

/// Get the newsroom verifying key
let impl_Server__get_newsroom_verifying_key (self: t_Server)
    : Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey =
  Core_models.Option.impl__map #Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
    #Securedrop_protocol.Sign.t_VerifyingKey
    (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
        self.f_newsroom_keys
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair)
    (fun keys ->
        let keys:Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair = keys in
        keys.Securedrop_protocol.Keys.Newsroom.f_vk)

/// Set the FPF signature for the newsroom
let impl_Server__set_fpf_signature
      (self: t_Server)
      (signature: Securedrop_protocol.Sign.t_Signature)
    : t_Server =
  let self:t_Server =
    {
      self with
      f_signature
      =
      Core_models.Option.Option_Some signature
      <:
      Core_models.Option.t_Option Securedrop_protocol.Sign.t_Signature
    }
    <:
    t_Server
  in
  self

/// Get the ephemeral key count for a journalist
let impl_Server__ephemeral_keys_count (self: t_Server) (journalist_id: Uuid.t_Uuid) : usize =
  Securedrop_protocol.Storage.impl_ServerStorage__ephemeral_keys_count self.f_storage journalist_id

/// Check if a journalist has ephemeral keys available
let impl_Server__has_ephemeral_keys (self: t_Server) (journalist_id: Uuid.t_Uuid) : bool =
  Securedrop_protocol.Storage.impl_ServerStorage__has_ephemeral_keys self.f_storage journalist_id

/// Find journalist ID by verifying key
let impl_Server__find_journalist_id
      (self: t_Server)
      (verifying_key: Securedrop_protocol.Sign.t_VerifyingKey)
    : Core_models.Option.t_Option Uuid.t_Uuid =
  Securedrop_protocol.Storage.impl_ServerStorage__find_journalist_by_verifying_key self.f_storage
    verifying_key

/// Check if a message exists with the given ID
let impl_Server__has_message (self: t_Server) (message_id: Uuid.t_Uuid) : bool =
  Hashbrown.Map.impl_5__contains_key #Uuid.t_Uuid
    #Securedrop_protocol.Messages.Core.t_Message
    #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    #Allocator_api2.Stable.Alloc.Global.t_Global
    #Uuid.t_Uuid
    (Securedrop_protocol.Storage.impl_ServerStorage__get_messages self.f_storage
      <:
      Hashbrown.Map.t_HashMap Uuid.t_Uuid
        Securedrop_protocol.Messages.Core.t_Message
        (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
        Allocator_api2.Stable.Alloc.Global.t_Global)
    message_id

/// Handle source newsroom key request (step 5)
let impl_Server__handle_source_newsroom_key_request
      (self: t_Server)
      (e_request: Securedrop_protocol.Messages.Core.t_SourceNewsroomKeyRequest)
    : Securedrop_protocol.Messages.Core.t_SourceNewsroomKeyResponse =
  {
    Securedrop_protocol.Messages.Core.f_newsroom_verifying_key
    =
    (Core_models.Option.impl__expect #Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
        (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair
            self.f_newsroom_keys
          <:
          Core_models.Option.t_Option Securedrop_protocol.Keys.Newsroom.t_NewsroomKeyPair)
        "Newsroom keys not found")
      .Securedrop_protocol.Keys.Newsroom.f_vk;
    Securedrop_protocol.Messages.Core.f_fpf_sig
    =
    Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_Signature
      #FStar.Tactics.Typeclasses.solve
      (Core_models.Option.impl__expect #Securedrop_protocol.Sign.t_Signature
          (Core_models.Option.impl__as_ref #Securedrop_protocol.Sign.t_Signature self.f_signature
            <:
            Core_models.Option.t_Option Securedrop_protocol.Sign.t_Signature)
          "FPF signature not found"
        <:
        Securedrop_protocol.Sign.t_Signature)
  }
  <:
  Securedrop_protocol.Messages.Core.t_SourceNewsroomKeyResponse

/// Handle source journalist key request (step 5)
let impl_Server__handle_source_journalist_key_request
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_Server)
      (e_request: Securedrop_protocol.Messages.Core.t_SourceJournalistKeyRequest)
      (rng: v_R)
    : (t_Server & v_R &
      Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
        Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse ()
  in
  let
  (tmp0: Securedrop_protocol.Storage.t_ServerStorage),
  (tmp1: v_R),
  (out:
    Alloc.Vec.t_Vec (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
      Alloc.Alloc.t_Global) =
    Securedrop_protocol.Storage.impl_ServerStorage__get_all_ephemeral_keys #v_R self.f_storage rng
  in
  let self:t_Server = { self with f_storage = tmp0 } <: t_Server in
  let rng:v_R = tmp1 in
  let journalist_ephemeral_keys:Alloc.Vec.t_Vec
    (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
    Alloc.Alloc.t_Global =
    out
  in
  let responses:Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
    Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
              (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
              Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          journalist_ephemeral_keys
        <:
        Alloc.Vec.Into_iter.t_IntoIter
          (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
          Alloc.Alloc.t_Global)
      responses
      (fun responses temp_1_ ->
          let responses:Alloc.Vec.t_Vec
            Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse Alloc.Alloc.t_Global =
            responses
          in
          let
          (journalist_id: Uuid.t_Uuid),
          (ephemeral_bundle: Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle) =
            temp_1_
          in
          let
          (signing_key: Securedrop_protocol.Sign.t_VerifyingKey),
          (fetching_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey),
          (reply_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey),
          (journalist_self_sig: Securedrop_protocol.Sign.t_SelfSignature),
          (newsroom_sig: Securedrop_protocol.Sign.t_Signature) =
            Core_models.Clone.f_clone #(Securedrop_protocol.Sign.t_VerifyingKey &
                Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                Securedrop_protocol.Sign.t_SelfSignature &
                Securedrop_protocol.Sign.t_Signature)
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__expect #(Securedrop_protocol.Sign.t_VerifyingKey &
                    Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                    Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                    Securedrop_protocol.Sign.t_SelfSignature &
                    Securedrop_protocol.Sign.t_Signature)
                  (Hashbrown.Map.impl_5__get #Uuid.t_Uuid
                      #(Securedrop_protocol.Sign.t_VerifyingKey &
                        Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                        Securedrop_protocol.Sign.t_SelfSignature &
                        Securedrop_protocol.Sign.t_Signature)
                      #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
                      #Allocator_api2.Stable.Alloc.Global.t_Global
                      #Uuid.t_Uuid
                      (Securedrop_protocol.Storage.impl_ServerStorage__get_journalists self
                            .f_storage
                        <:
                        Hashbrown.Map.t_HashMap Uuid.t_Uuid
                          (Securedrop_protocol.Sign.t_VerifyingKey &
                            Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                            Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                            Securedrop_protocol.Sign.t_SelfSignature &
                            Securedrop_protocol.Sign.t_Signature)
                          (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
                          Allocator_api2.Stable.Alloc.Global.t_Global)
                      journalist_id
                    <:
                    Core_models.Option.t_Option
                    (Securedrop_protocol.Sign.t_VerifyingKey &
                      Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                      Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                      Securedrop_protocol.Sign.t_SelfSignature &
                      Securedrop_protocol.Sign.t_Signature))
                  "Journalist should exist in storage"
                <:
                (Securedrop_protocol.Sign.t_VerifyingKey &
                  Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                  Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                  Securedrop_protocol.Sign.t_SelfSignature &
                  Securedrop_protocol.Sign.t_Signature))
          in
          let response:Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse =
            {
              Securedrop_protocol.Messages.Core.f_journalist_sig_pk = signing_key;
              Securedrop_protocol.Messages.Core.f_journalist_fetch_pk = fetching_key;
              Securedrop_protocol.Messages.Core.f_journalist_dhakem_sending_pk = reply_key;
              Securedrop_protocol.Messages.Core.f_newsroom_sig = newsroom_sig;
              Securedrop_protocol.Messages.Core.f_one_time_message_pq_pk
              =
              ephemeral_bundle.Securedrop_protocol.Keys.Journalist.f_public_keys
                .Securedrop_protocol.Keys.Journalist.f_one_time_message_pq_pk;
              Securedrop_protocol.Messages.Core.f_one_time_message_pk
              =
              ephemeral_bundle.Securedrop_protocol.Keys.Journalist.f_public_keys
                .Securedrop_protocol.Keys.Journalist.f_one_time_message_pk;
              Securedrop_protocol.Messages.Core.f_one_time_metadata_pk
              =
              ephemeral_bundle.Securedrop_protocol.Keys.Journalist.f_public_keys
                .Securedrop_protocol.Keys.Journalist.f_one_time_metadata_pk;
              Securedrop_protocol.Messages.Core.f_journalist_ephemeral_sig
              =
              ephemeral_bundle.Securedrop_protocol.Keys.Journalist.f_signature;
              Securedrop_protocol.Messages.Core.f_journalist_self_sig = journalist_self_sig
            }
            <:
            Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
          in
          let responses:Alloc.Vec.t_Vec
            Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
              #Alloc.Alloc.t_Global
              responses
              response
          in
          responses)
  in
  let hax_temp_output:Alloc.Vec.t_Vec
    Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse Alloc.Alloc.t_Global =
    responses
  in
  self, rng, hax_temp_output
  <:
  (t_Server & v_R &
    Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
      Alloc.Alloc.t_Global)

/// Handle message submission (step 6 for sources, step 9 for journalists)
let impl_Server__handle_message_submit
      (self: t_Server)
      (message: Securedrop_protocol.Messages.Core.t_Message)
    : (t_Server & Core_models.Result.t_Result Uuid.t_Uuid Anyhow.t_Error) =
  let message_id:Uuid.t_Uuid = Uuid.V4.impl__new_v4 () in
  let self:t_Server =
    {
      self with
      f_storage
      =
      Securedrop_protocol.Storage.impl_ServerStorage__add_message self.f_storage message_id message
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

/// Handle message ID fetch request (step 7)
/// TODO: Nothing here prevents someone from requesting messages
/// that aren't theirs? Should request messages have a signature?
let impl_Server__handle_message_id_fetch
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_Server)
      (e_request: Securedrop_protocol.Messages.Core.t_MessageChallengeFetchRequest)
      (rng: v_R)
    : (v_R &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
        Anyhow.t_Error) =
  let messages:Hashbrown.Map.t_HashMap Uuid.t_Uuid
    Securedrop_protocol.Messages.Core.t_Message
    (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    Allocator_api2.Stable.Alloc.Global.t_Global =
    Securedrop_protocol.Storage.impl_ServerStorage__get_messages self.f_storage
  in
  let message_count:usize =
    Hashbrown.Map.impl_4__len #Uuid.t_Uuid
      #Securedrop_protocol.Messages.Core.t_Message
      #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      #Allocator_api2.Stable.Alloc.Global.t_Global
      messages
  in
  let q_entries:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) ()
  in
  let cid_entries:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) ()
  in
  match
    Rust_primitives.Hax.Folds.fold_return (Core_models.Iter.Traits.Collect.f_into_iter #(Hashbrown.Map.t_Iter
              Uuid.t_Uuid Securedrop_protocol.Messages.Core.t_Message)
          #FStar.Tactics.Typeclasses.solve
          (Hashbrown.Map.impl_4__iter #Uuid.t_Uuid
              #Securedrop_protocol.Messages.Core.t_Message
              #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
              #Allocator_api2.Stable.Alloc.Global.t_Global
              messages
            <:
            Hashbrown.Map.t_Iter Uuid.t_Uuid Securedrop_protocol.Messages.Core.t_Message)
        <:
        Hashbrown.Map.t_Iter Uuid.t_Uuid Securedrop_protocol.Messages.Core.t_Message)
      (cid_entries, q_entries, rng
        <:
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          v_R))
      (fun temp_0_ temp_1_ ->
          let
          (cid_entries:
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
          (q_entries:
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let (message_id: Uuid.t_Uuid), (message: Securedrop_protocol.Messages.Core.t_Message) =
            temp_1_
          in
          let
          (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
          =
            Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
          in
          let rng:v_R = tmp0 in
          let y:t_Array u8 (mk_usize 32) =
            Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
              #Anyhow.t_Error
              out
              "Failed to generate random scalar"
          in
          let z_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey =
            Securedrop_protocol.Primitives.X25519.dh_public_key_from_scalar (Core_models.Result.impl__unwrap_or
                  #(t_Array u8 (mk_usize 32))
                  #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      #(t_Array u8 (mk_usize 32))
                      #FStar.Tactics.Typeclasses.solve
                      (Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          #FStar.Tactics.Typeclasses.solve
                          message.Securedrop_protocol.Messages.Core.f_dh_share_z
                        <:
                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    <:
                    Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                  (Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) <: t_Array u8 (mk_usize 32))
                <:
                t_Array u8 (mk_usize 32))
          in
          match
            Securedrop_protocol.Primitives.X25519.dh_shared_secret z_public_key y
            <:
            Core_models.Result.t_Result Securedrop_protocol.Primitives.X25519.t_DHSharedSecret
              Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok hoist60 ->
            let k_i:t_Array u8 (mk_usize 32) =
              Securedrop_protocol.Primitives.X25519.impl_DHSharedSecret__into_bytes hoist60
            in
            let x_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey =
              Securedrop_protocol.Primitives.X25519.dh_public_key_from_scalar (Core_models.Result.impl__unwrap_or
                    #(t_Array u8 (mk_usize 32))
                    #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                        #(t_Array u8 (mk_usize 32))
                        #FStar.Tactics.Typeclasses.solve
                        (Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            #FStar.Tactics.Typeclasses.solve
                            message.Securedrop_protocol.Messages.Core.f_dh_share_x
                          <:
                          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      <:
                      Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
                        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                    (Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) <: t_Array u8 (mk_usize 32))
                  <:
                  t_Array u8 (mk_usize 32))
            in
            (match
                Securedrop_protocol.Primitives.X25519.dh_shared_secret x_public_key y
                <:
                Core_models.Result.t_Result Securedrop_protocol.Primitives.X25519.t_DHSharedSecret
                  Anyhow.t_Error
              with
              | Core_models.Result.Result_Ok hoist61 ->
                let q_i:t_Array u8 (mk_usize 32) =
                  Securedrop_protocol.Primitives.X25519.impl_DHSharedSecret__into_bytes hoist61
                in
                let message_id_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                  Alloc.Slice.impl__to_vec #u8 (Uuid.impl_Uuid__as_bytes message_id <: t_Slice u8)
                in
                let cid_i:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                  Core_models.Result.impl__expect #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #Anyhow.t_Error
                    (Securedrop_protocol.Primitives.encrypt_message_id (k_i <: t_Slice u8)
                        (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            #FStar.Tactics.Typeclasses.solve
                            message_id_bytes
                          <:
                          t_Slice u8)
                      <:
                      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                        Anyhow.t_Error)
                    "Failed to encrypt message ID"
                in
                let q_entries:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global =
                  Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    q_entries
                    (Alloc.Slice.impl__to_vec #u8 (q_i <: t_Slice u8)
                      <:
                      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                in
                let cid_entries:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global =
                  Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #Alloc.Alloc.t_Global
                    cid_entries
                    cid_i
                in
                Core_models.Ops.Control_flow.ControlFlow_Continue
                (cid_entries, q_entries, rng
                  <:
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    v_R))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (v_R &
                        Core_models.Result.t_Result
                          Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                          Anyhow.t_Error)
                      (Prims.unit &
                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          v_R)))
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    v_R)
              | Core_models.Result.Result_Err err ->
                Core_models.Ops.Control_flow.ControlFlow_Break
                (Core_models.Ops.Control_flow.ControlFlow_Break
                  (rng,
                    (Core_models.Result.Result_Err err
                      <:
                      Core_models.Result.t_Result
                        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                        Anyhow.t_Error)
                    <:
                    (v_R &
                      Core_models.Result.t_Result
                        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                        Anyhow.t_Error))
                  <:
                  Core_models.Ops.Control_flow.t_ControlFlow
                    (v_R &
                      Core_models.Result.t_Result
                        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                        Anyhow.t_Error)
                    (Prims.unit &
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        v_R)))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (v_R &
                        Core_models.Result.t_Result
                          Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                          Anyhow.t_Error)
                      (Prims.unit &
                        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            Alloc.Alloc.t_Global &
                          v_R)))
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    v_R))
          | Core_models.Result.Result_Err err ->
            Core_models.Ops.Control_flow.ControlFlow_Break
            (Core_models.Ops.Control_flow.ControlFlow_Break
              (rng,
                (Core_models.Result.Result_Err err
                  <:
                  Core_models.Result.t_Result
                    Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error
                )
                <:
                (v_R &
                  Core_models.Result.t_Result
                    Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error
                ))
              <:
              Core_models.Ops.Control_flow.t_ControlFlow
                (v_R &
                  Core_models.Result.t_Result
                    Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error
                )
                (Prims.unit &
                  (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                    v_R)))
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow
                  (v_R &
                    Core_models.Result.t_Result
                      Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                      Anyhow.t_Error)
                  (Prims.unit &
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                      v_R)))
              (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                v_R))
    <:
    Core_models.Ops.Control_flow.t_ControlFlow
      (v_R &
        Core_models.Result.t_Result
          Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error)
      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
        v_R)
  with
  | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
  | Core_models.Ops.Control_flow.ControlFlow_Continue (cid_entries, q_entries, rng) ->
    match
      Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
            let
            (cid_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (q_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (rng: v_R) =
              temp_0_
            in
            true)
        (fun temp_0_ ->
            let
            (cid_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (q_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (rng: v_R) =
              temp_0_
            in
            (Alloc.Vec.impl_1__len #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                q_entries
              <:
              usize) <.
            Securedrop_protocol.Primitives.v_MESSAGE_ID_FETCH_SIZE
            <:
            bool)
        (fun temp_0_ ->
            let
            (cid_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (q_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (rng: v_R) =
              temp_0_
            in
            Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
        (cid_entries, q_entries, rng
          <:
          (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
            v_R))
        (fun temp_0_ ->
            let
            (cid_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (q_entries:
              Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global),
            (rng: v_R) =
              temp_0_
            in
            let
            (tmp0: v_R),
            (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
              Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
            in
            let rng:v_R = tmp0 in
            let random_y:t_Array u8 (mk_usize 32) =
              Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
                #Anyhow.t_Error
                out
                "Failed to generate random scalar"
            in
            let
            (tmp0: v_R),
            (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
              Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
            in
            let rng:v_R = tmp0 in
            let random_x:t_Array u8 (mk_usize 32) =
              Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
                #Anyhow.t_Error
                out
                "Failed to generate random scalar"
            in
            let random_x_pub:Securedrop_protocol.Primitives.X25519.t_DHPublicKey =
              Securedrop_protocol.Primitives.X25519.dh_public_key_from_scalar random_x
            in
            match
              Core_models.Result.impl__map_err #Securedrop_protocol.Primitives.X25519.t_DHSharedSecret
                #Anyhow.t_Error
                #Anyhow.t_Error
                (Securedrop_protocol.Primitives.X25519.dh_shared_secret random_x_pub random_y
                  <:
                  Core_models.Result.t_Result Securedrop_protocol.Primitives.X25519.t_DHSharedSecret
                    Anyhow.t_Error)
                (fun temp_0_ ->
                    let _:Anyhow.t_Error = temp_0_ in
                    let error:Anyhow.t_Error =
                      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                            (let list = ["failed to construct shared secret"] in
                              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                              Rust_primitives.Hax.array_of_list 1 list)
                          <:
                          Core_models.Fmt.t_Arguments)
                    in
                    Anyhow.__private.must_use error)
              <:
              Core_models.Result.t_Result Securedrop_protocol.Primitives.X25519.t_DHSharedSecret
                Anyhow.t_Error
            with
            | Core_models.Result.Result_Ok hoist64 ->
              let random_q:t_Array u8 (mk_usize 32) =
                Securedrop_protocol.Primitives.X25519.impl_DHSharedSecret__into_bytes hoist64
              in
              let random_uuid:Uuid.t_Uuid = Uuid.V4.impl__new_v4 () in
              let
              (tmp0: v_R),
              (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
                Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
              in
              let rng:v_R = tmp0 in
              let random_key:t_Array u8 (mk_usize 32) =
                Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
                  #Anyhow.t_Error
                  out
                  "Failed to generate random key"
              in
              let random_cid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                Core_models.Result.impl__expect #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #Anyhow.t_Error
                  (Securedrop_protocol.Primitives.encrypt_message_id (random_key <: t_Slice u8)
                      (Uuid.impl_Uuid__as_bytes random_uuid <: t_Slice u8)
                    <:
                    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      Anyhow.t_Error)
                  "Failed to encrypt random UUID"
              in
              let q_entries:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global =
                Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #Alloc.Alloc.t_Global
                  q_entries
                  (Alloc.Slice.impl__to_vec #u8 (random_q <: t_Slice u8)
                    <:
                    Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              in
              let cid_entries:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                Alloc.Alloc.t_Global =
                Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #Alloc.Alloc.t_Global
                  cid_entries
                  random_cid
              in
              Core_models.Ops.Control_flow.ControlFlow_Continue
              (cid_entries, q_entries, rng
                <:
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  v_R))
              <:
              Core_models.Ops.Control_flow.t_ControlFlow
                (Core_models.Ops.Control_flow.t_ControlFlow
                    (v_R &
                      Core_models.Result.t_Result
                        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                        Anyhow.t_Error)
                    (Prims.unit &
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        v_R)))
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  v_R)
            | Core_models.Result.Result_Err err ->
              Core_models.Ops.Control_flow.ControlFlow_Break
              (Core_models.Ops.Control_flow.ControlFlow_Break
                (rng,
                  (Core_models.Result.Result_Err err
                    <:
                    Core_models.Result.t_Result
                      Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                      Anyhow.t_Error)
                  <:
                  (v_R &
                    Core_models.Result.t_Result
                      Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                      Anyhow.t_Error))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (v_R &
                    Core_models.Result.t_Result
                      Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                      Anyhow.t_Error)
                  (Prims.unit &
                    (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                      Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                      v_R)))
              <:
              Core_models.Ops.Control_flow.t_ControlFlow
                (Core_models.Ops.Control_flow.t_ControlFlow
                    (v_R &
                      Core_models.Result.t_Result
                        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse
                        Anyhow.t_Error)
                    (Prims.unit &
                      (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Alloc.Alloc.t_Global &
                        v_R)))
                (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
                  v_R))
      <:
      Core_models.Ops.Control_flow.t_ControlFlow
        (v_R &
          Core_models.Result.t_Result
            Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error)
        (Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global &
          v_R)
    with
    | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
    | Core_models.Ops.Control_flow.ControlFlow_Continue (cid_entries, q_entries, rng) ->
      let
      (pairs:
        Alloc.Vec.t_Vec
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Alloc.Alloc.t_Global =
        Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Zip.t_Zip
              (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global)
              (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global))
          #FStar.Tactics.Typeclasses.solve
          #(Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global)
          (Core_models.Iter.Traits.Iterator.f_zip #(Alloc.Vec.Into_iter.t_IntoIter
                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
              (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  q_entries
                <:
                Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global)
              cid_entries
            <:
            Core_models.Iter.Adapters.Zip.t_Zip
              (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global)
              (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  Alloc.Alloc.t_Global))
      in
      let shuffled:Alloc.Vec.t_Vec
        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Alloc.Alloc.t_Global =
        Alloc.Slice.impl__to_vec #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          (Rust_primitives.Hax.failure "At this position, Hax was expecting an expression of the shape `&mut _`.\nHax forbids `f(x)` (where `f` expects a mutable reference as input) when `x` is not a [1mplace expression[0m[90m[1][0m or when it is a dereference expression.\n\n[1]: https://doc.rust-lang.org/reference/expressions.html#place-expressions-and-value-expressions\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
              "deref(\n core_models::option::impl__expect::<\n &mut [tuple2<\n alloc::vec::t_Vec<int, alloc::alloc::t_Global>,\n alloc::vec::t_Vec<int, alloc::alloc::t_Global>,\n >],\n >(\n securedrop_protocol::server::imp..."

            <:
            t_Slice
            (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      in
      let q_entries, cid_entries:(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global) =
        Core_models.Iter.Traits.Iterator.f_unzip #(Alloc.Vec.Into_iter.t_IntoIter
              (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
          #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
          (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
                  ) Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              shuffled
            <:
            Alloc.Vec.Into_iter.t_IntoIter
              (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global)
      in
      let hax_temp_output:Core_models.Result.t_Result
        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error =
        Core_models.Result.Result_Ok
        ({
            Securedrop_protocol.Messages.Core.f_count
            =
            Securedrop_protocol.Primitives.v_MESSAGE_ID_FETCH_SIZE;
            Securedrop_protocol.Messages.Core.f_messages
            =
            Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Zip.t_Zip
                  (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global)
                  (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global))
              #FStar.Tactics.Typeclasses.solve
              #(Alloc.Vec.t_Vec
                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
                  ) Alloc.Alloc.t_Global)
              (Core_models.Iter.Traits.Iterator.f_zip #(Alloc.Vec.Into_iter.t_IntoIter
                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  #(Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                  (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
                          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      q_entries
                    <:
                    Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global)
                  cid_entries
                <:
                Core_models.Iter.Adapters.Zip.t_Zip
                  (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global)
                  (Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      Alloc.Alloc.t_Global))
          }
          <:
          Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse)
        <:
        Core_models.Result.t_Result
          Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error
      in
      rng, hax_temp_output
      <:
      (v_R &
        Core_models.Result.t_Result
          Securedrop_protocol.Messages.Core.t_MessageChallengeFetchResponse Anyhow.t_Error)

/// Shuffle challenges so that real and decoys are interspersed.
/// Note: not a true random shuffle, toybox impl only
let impl_Server__shuffle_not_for_prod
      (vec:
          Alloc.Vec.t_Vec
            (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            Alloc.Alloc.t_Global)
    : Rust_primitives.Hax.failure =
  Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
    "{\n let _: tuple0 = {\n (if alloc::vec::impl_1__is_empty::<\n tuple2<\n alloc::vec::t_Vec<int, alloc::alloc::t_Global>,\n alloc::vec::t_Vec<int, alloc::alloc::t_Global>,\n >,\n alloc::alloc::t_Global,\n >(&(v..."

/// Handle message fetch request (step 8/10)
let impl_Server__handle_message_fetch
      (self: t_Server)
      (e_request: Securedrop_protocol.Messages.Core.t_MessageFetchRequest)
    : Core_models.Option.t_Option Securedrop_protocol.Messages.Core.t_MessageBundle =
  Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic "not implemented"
      <:
      Rust_primitives.Hax.t_Never)

/// Process a new refresh request from the journalist.
/// TODO: The caller should persist the keys for J.
/// Step 3.2 in the 0.2 spec.
/// TODO(later): How to handle signing when offline? (Not relevant for benchmarking)
let impl_Server__handle_journalist_refresh
      (self: t_Server)
      (e_request: Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest)
    : (t_Server & Core_models.Result.t_Result Prims.unit Anyhow.t_Error) =
  let hax_temp_output:Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
    Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic "not implemented"
        <:
        Rust_primitives.Hax.t_Never)
  in
  self, hax_temp_output <: (t_Server & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
