module Securedrop_protocol.Source
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol.Client in
  let open Securedrop_protocol.Messages.Core in
  let open Securedrop_protocol.Primitives.Dh_akem in
  let open Securedrop_protocol.Primitives.Mlkem in
  let open Securedrop_protocol.Primitives.X25519 in
  let open Securedrop_protocol.Primitives.Xwing in
  let open Securedrop_protocol.Sign in
  ()

/// Source session for interacting with the server
/// TODO: Load from storage
type t_SourceClient = {
  f_key_bundle:Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle;
  f_newsroom_verifying_key:Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey
}

let impl_4: Core_models.Clone.t_Clone t_SourceClient =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Initialize source session with keys derived from passphrase (Protocol Step 4)
let impl_SourceClient__initialize_with_passphrase
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (Securedrop_protocol.Keys.Source.t_SourcePassphrase & t_SourceClient) =
  let
  (passphrase: Securedrop_protocol.Keys.Source.t_SourcePassphrase),
  (key_bundle: Securedrop_protocol.Keys.Source.t_SourceKeyBundle) =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::source::impl_SourceKeyBundle__new::<&mut R>(&mut (rng))"
  in
  let session:t_SourceClient =
    {
      f_key_bundle
      =
      Core_models.Option.Option_Some key_bundle
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle;
      f_newsroom_verifying_key
      =
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey
    }
    <:
    t_SourceClient
  in
  passphrase, session <: (Securedrop_protocol.Keys.Source.t_SourcePassphrase & t_SourceClient)

/// Initialize source session from existing passphrase (Protocol Step 4)
let impl_SourceClient__from_passphrase (passphrase: t_Slice u8) : t_SourceClient =
  let key_bundle:Securedrop_protocol.Keys.Source.t_SourceKeyBundle =
    Securedrop_protocol.Keys.Source.impl_SourceKeyBundle__from_passphrase passphrase
  in
  {
    f_key_bundle
    =
    Core_models.Option.Option_Some key_bundle
    <:
    Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle;
    f_newsroom_verifying_key
    =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey
  }
  <:
  t_SourceClient

/// Get the source's key bundle
let impl_SourceClient__key_bundle (self: t_SourceClient)
    : Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle =
  Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
    self.f_key_bundle

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Securedrop_protocol.Client.t_Client t_SourceClient =
  {
    f_NewsroomKey = Securedrop_protocol.Sign.t_VerifyingKey;
    f_newsroom_verifying_key_pre = (fun (self: t_SourceClient) -> true);
    f_newsroom_verifying_key_post
    =
    (fun
        (self: t_SourceClient)
        (out: Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey)
        ->
        true);
    f_newsroom_verifying_key
    =
    (fun (self: t_SourceClient) ->
        Core_models.Option.impl__as_ref #Securedrop_protocol.Sign.t_VerifyingKey
          self.f_newsroom_verifying_key);
    f_set_newsroom_verifying_key_pre
    =
    (fun (self: t_SourceClient) (key: Securedrop_protocol.Sign.t_VerifyingKey) -> true);
    f_set_newsroom_verifying_key_post
    =
    (fun
        (self: t_SourceClient)
        (key: Securedrop_protocol.Sign.t_VerifyingKey)
        (out: t_SourceClient)
        ->
        true);
    f_set_newsroom_verifying_key
    =
    (fun (self: t_SourceClient) (key: Securedrop_protocol.Sign.t_VerifyingKey) ->
        let self:t_SourceClient =
          {
            self with
            f_newsroom_verifying_key
            =
            Core_models.Option.Option_Some key
            <:
            Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey
          }
          <:
          t_SourceClient
        in
        self);
    f_fetch_message_ids_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
        (self: t_SourceClient)
        (e_rng: v_R)
        ->
        true);
    f_fetch_message_ids_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
        (self: t_SourceClient)
        (e_rng: v_R)
        (out: (v_R & Securedrop_protocol.Messages.Core.t_MessageChallengeFetchRequest))
        ->
        true);
    f_fetch_message_ids
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_SourceClient)
      (e_rng: v_R)
      ->
      let hax_temp_output:Securedrop_protocol.Messages.Core.t_MessageChallengeFetchRequest =
        Securedrop_protocol.Messages.Core.MessageChallengeFetchRequest
        <:
        Securedrop_protocol.Messages.Core.t_MessageChallengeFetchRequest
      in
      e_rng, hax_temp_output
      <:
      (v_R & Securedrop_protocol.Messages.Core.t_MessageChallengeFetchRequest)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Securedrop_protocol.Client.t_ClientPrivate t_SourceClient =
  {
    f_fetching_private_key_pre = (fun (self: t_SourceClient) -> true);
    f_fetching_private_key_post
    =
    (fun
        (self: t_SourceClient)
        (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
        ->
        true);
    f_fetching_private_key
    =
    (fun (self: t_SourceClient) ->
        Core_models.Result.Result_Ok
        (Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__into_bytes (Core_models.Clone.f_clone
                #Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
                #FStar.Tactics.Typeclasses.solve
                (Core_models.Option.impl__unwrap #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
                    (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
                        self.f_key_bundle
                      <:
                      Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle)
                  <:
                  Securedrop_protocol.Keys.Source.t_SourceKeyBundle)
                  .Securedrop_protocol.Keys.Source.f_fetch
                  .Securedrop_protocol.Keys.Source.f_private_key
              <:
              Securedrop_protocol.Primitives.X25519.t_DHPrivateKey))
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error);
    f_message_enc_private_key_dhakem_pre = (fun (self: t_SourceClient) -> true);
    f_message_enc_private_key_dhakem_post
    =
    (fun
        (self: t_SourceClient)
        (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
        ->
        true);
    f_message_enc_private_key_dhakem
    =
    fun (self: t_SourceClient) ->
      Core_models.Result.Result_Ok
      (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes (Core_models.Clone.f_clone
              #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__unwrap #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
                  (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
                      self.f_key_bundle
                    <:
                    Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle)
                <:
                Securedrop_protocol.Keys.Source.t_SourceKeyBundle)
                .Securedrop_protocol.Keys.Source.f_message_encrypt_dhakem
                .Securedrop_protocol.Keys.Source.f_private_key
            <:
            Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey))
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  }

/// Fetch newsroom keys (step 5)
let impl_SourceClient__fetch_newsroom_keys (self: t_SourceClient)
    : Securedrop_protocol.Messages.Core.t_SourceNewsroomKeyRequest =
  Securedrop_protocol.Messages.Core.SourceNewsroomKeyRequest
  <:
  Securedrop_protocol.Messages.Core.t_SourceNewsroomKeyRequest

/// Handle and verify newsroom key response (step 5)
/// This verifies the FPF signature on the newsroom's verifying key
/// and stores the verified key in the session.
let impl_SourceClient__handle_newsroom_key_response
      (self: t_SourceClient)
      (response: Securedrop_protocol.Messages.Core.t_SourceNewsroomKeyResponse)
      (fpf_verifying_key: Securedrop_protocol.Sign.t_VerifyingKey)
    : (t_SourceClient & Core_models.Result.t_Result Prims.unit Anyhow.t_Error) =
  let newsroom_vk_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes response
        .Securedrop_protocol.Messages.Core.f_newsroom_verifying_key
  in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Anyhow.t_Error
      #Anyhow.t_Error
      (Securedrop_protocol.Sign.impl_VerifyingKey__verify fpf_verifying_key
          (newsroom_vk_bytes <: t_Slice u8)
          response.Securedrop_protocol.Messages.Core.f_fpf_sig
        <:
        Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
      (fun temp_0_ ->
          let _:Anyhow.t_Error = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["Invalid FPF signature on newsroom verifying key"] in
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
    let self:t_SourceClient =
      {
        self with
        f_newsroom_verifying_key
        =
        Core_models.Option.Option_Some
        response.Securedrop_protocol.Messages.Core.f_newsroom_verifying_key
        <:
        Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey
      }
      <:
      t_SourceClient
    in
    let hax_temp_output:Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
      Core_models.Result.Result_Ok (() <: Prims.unit)
      <:
      Core_models.Result.t_Result Prims.unit Anyhow.t_Error
    in
    self, hax_temp_output
    <:
    (t_SourceClient & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err <: Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
    <:
    (t_SourceClient & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)

/// Fetch journalist keys (step 5)
let impl_SourceClient__fetch_journalist_keys (self: t_SourceClient)
    : Securedrop_protocol.Messages.Core.t_SourceJournalistKeyRequest =
  Securedrop_protocol.Messages.Core.SourceJournalistKeyRequest
  <:
  Securedrop_protocol.Messages.Core.t_SourceJournalistKeyRequest

/// Handle and verify journalist key response (step 5)
/// This verifies the newsroom signature on the journalist's keys
/// and the journalist signature on the ephemeral keys.
let impl_SourceClient__handle_journalist_key_response
      (self: t_SourceClient)
      (response: Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse)
      (newsroom_verifying_key: Securedrop_protocol.Sign.t_VerifyingKey)
    : Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Anyhow.t_Error
      #Anyhow.t_Error
      (Securedrop_protocol.Sign.impl_VerifyingKey__verify newsroom_verifying_key
          (Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes response
                .Securedrop_protocol.Messages.Core.f_journalist_sig_pk
            <:
            t_Slice u8)
          response.Securedrop_protocol.Messages.Core.f_newsroom_sig
        <:
        Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
      (fun temp_0_ ->
          let _:Anyhow.t_Error = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["Invalid newsroom signature on journalist keys"] in
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
    let public_keys:Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys =
      {
        Securedrop_protocol.Keys.Journalist.f_reply_key
        =
        Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
          #FStar.Tactics.Typeclasses.solve
          response.Securedrop_protocol.Messages.Core.f_journalist_dhakem_sending_pk;
        Securedrop_protocol.Keys.Journalist.f_fetch_key
        =
        Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
          #FStar.Tactics.Typeclasses.solve
          response.Securedrop_protocol.Messages.Core.f_journalist_fetch_pk
      }
      <:
      Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys
    in
    let enrollment_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistEnrollmentKeyBundle =
      {
        Securedrop_protocol.Keys.Journalist.f_signing_key
        =
        response.Securedrop_protocol.Messages.Core.f_journalist_sig_pk;
        Securedrop_protocol.Keys.Journalist.f_public_keys = public_keys;
        Securedrop_protocol.Keys.Journalist.f_self_signature
        =
        Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_SelfSignature
          #FStar.Tactics.Typeclasses.solve
          response.Securedrop_protocol.Messages.Core.f_journalist_self_sig
      }
      <:
      Securedrop_protocol.Keys.Journalist.t_JournalistEnrollmentKeyBundle
    in
    let enrollment_signature:Securedrop_protocol.Sign.t_Signature =
      Securedrop_protocol.Sign.impl_SelfSignature__as_signature (Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_SelfSignature
            #FStar.Tactics.Typeclasses.solve
            enrollment_bundle.Securedrop_protocol.Keys.Journalist.f_self_signature
          <:
          Securedrop_protocol.Sign.t_SelfSignature)
    in
    (match
        Core_models.Result.impl__map_err #Prims.unit
          #Anyhow.t_Error
          #Anyhow.t_Error
          (Securedrop_protocol.Sign.impl_VerifyingKey__verify enrollment_bundle
                .Securedrop_protocol.Keys.Journalist.f_signing_key
              (Securedrop_protocol.Keys.Journalist.impl_JournalistLongtermPublicKeys__into_bytes enrollment_bundle
                    .Securedrop_protocol.Keys.Journalist.f_public_keys
                <:
                t_Slice u8)
              enrollment_signature
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
          (fun temp_0_ ->
              let _:Anyhow.t_Error = temp_0_ in
              let error:Anyhow.t_Error =
                Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                      (let list = ["Invalid self-signature on journalist keys"] in
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
        let one_time_keys:Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys =
          {
            Securedrop_protocol.Keys.Journalist.f_one_time_message_pq_pk
            =
            Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey
              #FStar.Tactics.Typeclasses.solve
              response.Securedrop_protocol.Messages.Core.f_one_time_message_pq_pk;
            Securedrop_protocol.Keys.Journalist.f_one_time_message_pk
            =
            Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
              #FStar.Tactics.Typeclasses.solve
              response.Securedrop_protocol.Messages.Core.f_one_time_message_pk;
            Securedrop_protocol.Keys.Journalist.f_one_time_metadata_pk
            =
            Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey
              #FStar.Tactics.Typeclasses.solve
              response.Securedrop_protocol.Messages.Core.f_one_time_metadata_pk
          }
          <:
          Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys
        in
        (match
            Core_models.Result.impl__map_err #Prims.unit
              #Anyhow.t_Error
              #Anyhow.t_Error
              (Securedrop_protocol.Sign.impl_VerifyingKey__verify response
                    .Securedrop_protocol.Messages.Core.f_journalist_sig_pk
                  (Securedrop_protocol.Keys.Journalist.impl_JournalistOneTimePublicKeys__into_bytes one_time_keys

                    <:
                    t_Slice u8)
                  response.Securedrop_protocol.Messages.Core.f_journalist_ephemeral_sig
                <:
                Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
              (fun temp_0_ ->
                  let _:Anyhow.t_Error = temp_0_ in
                  let error:Anyhow.t_Error =
                    Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                          (let list = ["Invalid journalist signature on one-time keys"] in
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
            Core_models.Result.Result_Ok (() <: Prims.unit)
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error
          | Core_models.Result.Result_Err err ->
            Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err <: Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result Prims.unit Anyhow.t_Error

/// Submit a message (step 6)
let impl_SourceClient__submit_message
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_SourceClient)
      (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (journalist_responses:
          t_Slice Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse)
      (rng: v_R)
    : (v_R &
      Core_models.Result.t_Result
        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
        Anyhow.t_Error) =
  match
    Core_models.Option.impl__ok_or_else #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
      #Anyhow.t_Error
      (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Source.t_SourceKeyBundle
          self.f_key_bundle
        <:
        Core_models.Option.t_Option Securedrop_protocol.Keys.Source.t_SourceKeyBundle)
      (fun temp_0_ ->
          let _:Prims.unit = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["Source key bundle not initialized"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Securedrop_protocol.Keys.Source.t_SourceKeyBundle Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok key_bundle ->
    let requests:Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global =
      Alloc.Vec.impl__new #Securedrop_protocol.Messages.Core.t_Message ()
    in
    (match
        Rust_primitives.Hax.Folds.fold_return (Core_models.Iter.Traits.Collect.f_into_iter #(t_Slice
                Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse)
              #FStar.Tactics.Typeclasses.solve
              journalist_responses
            <:
            Core_models.Slice.Iter.t_Iter
            Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse)
          (requests, rng
            <:
            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global & v_R)
          )
          (fun temp_0_ journalist_response ->
              let
              (requests:
                Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global),
              (rng: v_R) =
                temp_0_
              in
              let journalist_response:Securedrop_protocol.Messages.Core.t_SourceJournalistKeyResponse
              =
                journalist_response
              in
              match
                Securedrop_protocol.Client.f_get_newsroom_verifying_key #t_SourceClient
                  #FStar.Tactics.Typeclasses.solve
                  self
                <:
                Core_models.Result.t_Result Securedrop_protocol.Sign.t_VerifyingKey Anyhow.t_Error
              with
              | Core_models.Result.Result_Ok hoist66 ->
                let source_message:Securedrop_protocol.Messages.Core.t_SourceMessage =
                  {
                    Securedrop_protocol.Messages.Core.f_message
                    =
                    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      message;
                    Securedrop_protocol.Messages.Core.f_source_message_pq_pk
                    =
                    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey
                      #FStar.Tactics.Typeclasses.solve
                      key_bundle.Securedrop_protocol.Keys.Source.f_pq_kem_psk
                        .Securedrop_protocol.Keys.Source.f_public_key;
                    Securedrop_protocol.Messages.Core.f_source_message_pk
                    =
                    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
                      #FStar.Tactics.Typeclasses.solve
                      key_bundle.Securedrop_protocol.Keys.Source.f_message_encrypt_dhakem
                        .Securedrop_protocol.Keys.Source.f_public_key;
                    Securedrop_protocol.Messages.Core.f_source_metadata_pk
                    =
                    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey
                      #FStar.Tactics.Typeclasses.solve
                      key_bundle.Securedrop_protocol.Keys.Source.f_metadata
                        .Securedrop_protocol.Keys.Source.f_public_key;
                    Securedrop_protocol.Messages.Core.f_source_fetch_pk
                    =
                    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
                      #FStar.Tactics.Typeclasses.solve
                      key_bundle.Securedrop_protocol.Keys.Source.f_fetch
                        .Securedrop_protocol.Keys.Source.f_public_key;
                    Securedrop_protocol.Messages.Core.f_journalist_sig_pk
                    =
                    journalist_response.Securedrop_protocol.Messages.Core.f_journalist_sig_pk;
                    Securedrop_protocol.Messages.Core.f_newsroom_sig_pk
                    =
                    Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_VerifyingKey
                      #FStar.Tactics.Typeclasses.solve
                      hoist66
                  }
                  <:
                  Securedrop_protocol.Messages.Core.t_SourceMessage
                in
                let
                (tmp0: v_R),
                (out:
                  Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message
                    Anyhow.t_Error) =
                  Securedrop_protocol.Client.f_submit_structured_message #t_SourceClient
                    #FStar.Tactics.Typeclasses.solve
                    #Securedrop_protocol.Messages.Core.t_SourceMessage #v_R self source_message
                    (journalist_response.Securedrop_protocol.Messages.Core.f_one_time_message_pk,
                      journalist_response.Securedrop_protocol.Messages.Core.f_one_time_message_pq_pk
                      <:
                      (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                        Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey))
                    journalist_response.Securedrop_protocol.Messages.Core.f_one_time_metadata_pk
                    journalist_response.Securedrop_protocol.Messages.Core.f_journalist_fetch_pk
                    key_bundle.Securedrop_protocol.Keys.Source.f_message_encrypt_dhakem
                      .Securedrop_protocol.Keys.Source.f_private_key
                    key_bundle.Securedrop_protocol.Keys.Source.f_message_encrypt_dhakem
                      .Securedrop_protocol.Keys.Source.f_public_key rng
                in
                let rng:v_R = tmp0 in
                (match
                    out
                    <:
                    Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message
                      Anyhow.t_Error
                  with
                  | Core_models.Result.Result_Ok request ->
                    let requests:Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                      Alloc.Alloc.t_Global =
                      Alloc.Vec.impl_1__push #Securedrop_protocol.Messages.Core.t_Message
                        #Alloc.Alloc.t_Global
                        requests
                        request
                    in
                    Core_models.Ops.Control_flow.ControlFlow_Continue
                    (requests, rng
                      <:
                      (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                          Alloc.Alloc.t_Global &
                        v_R))
                    <:
                    Core_models.Ops.Control_flow.t_ControlFlow
                      (Core_models.Ops.Control_flow.t_ControlFlow
                          (v_R &
                            Core_models.Result.t_Result
                              (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                  Alloc.Alloc.t_Global) Anyhow.t_Error)
                          (Prims.unit &
                            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                Alloc.Alloc.t_Global &
                              v_R)))
                      (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                          Alloc.Alloc.t_Global &
                        v_R)
                  | Core_models.Result.Result_Err err ->
                    Core_models.Ops.Control_flow.ControlFlow_Break
                    (Core_models.Ops.Control_flow.ControlFlow_Break
                      (rng,
                        (Core_models.Result.Result_Err err
                          <:
                          Core_models.Result.t_Result
                            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                Alloc.Alloc.t_Global) Anyhow.t_Error)
                        <:
                        (v_R &
                          Core_models.Result.t_Result
                            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                Alloc.Alloc.t_Global) Anyhow.t_Error))
                      <:
                      Core_models.Ops.Control_flow.t_ControlFlow
                        (v_R &
                          Core_models.Result.t_Result
                            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                Alloc.Alloc.t_Global) Anyhow.t_Error)
                        (Prims.unit &
                          (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                              Alloc.Alloc.t_Global &
                            v_R)))
                    <:
                    Core_models.Ops.Control_flow.t_ControlFlow
                      (Core_models.Ops.Control_flow.t_ControlFlow
                          (v_R &
                            Core_models.Result.t_Result
                              (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                  Alloc.Alloc.t_Global) Anyhow.t_Error)
                          (Prims.unit &
                            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                                Alloc.Alloc.t_Global &
                              v_R)))
                      (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                          Alloc.Alloc.t_Global &
                        v_R))
              | Core_models.Result.Result_Err err ->
                Core_models.Ops.Control_flow.ControlFlow_Break
                (Core_models.Ops.Control_flow.ControlFlow_Break
                  (rng,
                    (Core_models.Result.Result_Err err
                      <:
                      Core_models.Result.t_Result
                        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                            Alloc.Alloc.t_Global) Anyhow.t_Error)
                    <:
                    (v_R &
                      Core_models.Result.t_Result
                        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                            Alloc.Alloc.t_Global) Anyhow.t_Error))
                  <:
                  Core_models.Ops.Control_flow.t_ControlFlow
                    (v_R &
                      Core_models.Result.t_Result
                        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                            Alloc.Alloc.t_Global) Anyhow.t_Error)
                    (Prims.unit &
                      (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                          Alloc.Alloc.t_Global &
                        v_R)))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (v_R &
                        Core_models.Result.t_Result
                          (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                              Alloc.Alloc.t_Global) Anyhow.t_Error)
                      (Prims.unit &
                        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message
                            Alloc.Alloc.t_Global &
                          v_R)))
                  (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global &
                    v_R))
        <:
        Core_models.Ops.Control_flow.t_ControlFlow
          (v_R &
            Core_models.Result.t_Result
              (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
              Anyhow.t_Error)
          (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global & v_R)
      with
      | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core_models.Ops.Control_flow.ControlFlow_Continue (requests, rng) ->
        let hax_temp_output:Core_models.Result.t_Result
          (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
          Anyhow.t_Error =
          Core_models.Result.Result_Ok requests
          <:
          Core_models.Result.t_Result
            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
            Anyhow.t_Error
        in
        rng, hax_temp_output
        <:
        (v_R &
          Core_models.Result.t_Result
            (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
            Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result
        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
        Anyhow.t_Error)
    <:
    (v_R &
      Core_models.Result.t_Result
        (Alloc.Vec.t_Vec Securedrop_protocol.Messages.Core.t_Message Alloc.Alloc.t_Global)
        Anyhow.t_Error)
