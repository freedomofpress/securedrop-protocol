module Securedrop_protocol.Journalist
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  let open Securedrop_protocol.Client in
  let open Securedrop_protocol.Keys.Journalist in
  let open Securedrop_protocol.Messages.Core in
  let open Securedrop_protocol.Primitives.Dh_akem in
  let open Securedrop_protocol.Primitives.X25519 in
  let open Securedrop_protocol.Sign in
  ()

/// Journalist session for interacting with the server
/// TODO: All this stuff should be persisted to disk.
type t_JournalistClient = {
  f_signing_key:Core_models.Option.t_Option
  Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair;
  f_fetching_key:Core_models.Option.t_Option
  Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair;
  f_message_send_dhakem_key:Core_models.Option.t_Option
  Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair;
  f_one_time_keystore:Alloc.Vec.t_Vec
    Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeypairs Alloc.Alloc.t_Global;
  f_newsroom_verifying_key:Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey;
  f_self_signature:Core_models.Option.t_Option Securedrop_protocol.Sign.t_SelfSignature
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Default.t_Default t_JournalistClient

unfold
let impl_4 = impl_4'

/// Create a new journalist session
/// TODO: Load from storage
let impl_JournalistClient__new (_: Prims.unit) : t_JournalistClient =
  Core_models.Default.f_default #t_JournalistClient #FStar.Tactics.Typeclasses.solve ()

/// Sign a message.
let impl_JournalistClient__sign (self: t_JournalistClient) (message: t_Slice u8)
    : Core_models.Result.t_Result Securedrop_protocol.Sign.t_Signature Anyhow.t_Error =
  match
    Core_models.Option.impl__ok_or_else #Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
      #Anyhow.t_Error
      (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
          self.f_signing_key
        <:
        Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair)
      (fun temp_0_ ->
          let _:Prims.unit = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list =
                      ["No signing key found in session. Call create_setup_request first."]
                    in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
      Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok signing_key ->
    Core_models.Result.Result_Ok
    (Securedrop_protocol.Keys.Journalist.impl_JournalistSigningKeyPair__sign signing_key message)
    <:
    Core_models.Result.t_Result Securedrop_protocol.Sign.t_Signature Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result Securedrop_protocol.Sign.t_Signature Anyhow.t_Error

/// Generate a new journalist setup request.
/// This generates the journalist's key pairs and creates a setup request
/// containing only the public keys to send to the newsroom.
/// TODO: The caller (eventual CLI) should persist these keys to disk.
let impl_JournalistClient__create_setup_request
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_JournalistClient)
      (rng: v_R)
    : (t_JournalistClient &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupRequest
        Anyhow.t_Error) =
  let signing_key:Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistSigningKeyPair__new::<\n &mut R,\n >(&mut (rng))"

  in
  let fetching_key:Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistFetchKeyPair__new::<\n &mut R,\n >(&mut (rng))"

  in
  let reply_key:Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistReplyClassicalKeyPair__generate::<\n &mut R,\n >(&mut (rng))"

  in
  let signing_vk:Securedrop_protocol.Sign.t_VerifyingKey =
    signing_key.Securedrop_protocol.Keys.Journalist.f_vk
  in
  let fetching_pk:Securedrop_protocol.Primitives.X25519.t_DHPublicKey =
    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
      #FStar.Tactics.Typeclasses.solve
      fetching_key.Securedrop_protocol.Keys.Journalist.f_public_key
  in
  let reply_key_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey =
    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
      #FStar.Tactics.Typeclasses.solve
      reply_key.Securedrop_protocol.Keys.Journalist.f_public_key
  in
  let self:t_JournalistClient =
    {
      self with
      f_signing_key
      =
      Core_models.Option.Option_Some signing_key
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
    }
    <:
    t_JournalistClient
  in
  let self:t_JournalistClient =
    {
      self with
      f_fetching_key
      =
      Core_models.Option.Option_Some fetching_key
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
    }
    <:
    t_JournalistClient
  in
  let self:t_JournalistClient =
    {
      self with
      f_message_send_dhakem_key
      =
      Core_models.Option.Option_Some reply_key
      <:
      Core_models.Option.t_Option
      Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
    }
    <:
    t_JournalistClient
  in
  let longterm_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys =
    {
      Securedrop_protocol.Keys.Journalist.f_fetch_key = fetching_pk;
      Securedrop_protocol.Keys.Journalist.f_reply_key = reply_key_pk
    }
    <:
    Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys
  in
  let pubkey_bytes:t_Array u8 (mk_usize 64) =
    Securedrop_protocol.Keys.Journalist.impl_JournalistLongtermPublicKeys__into_bytes (Core_models.Clone.f_clone
          #Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys
          #FStar.Tactics.Typeclasses.solve
          longterm_bundle
        <:
        Securedrop_protocol.Keys.Journalist.t_JournalistLongtermPublicKeys)
  in
  let self_signature:Securedrop_protocol.Sign.t_SelfSignature =
    Securedrop_protocol.Sign.SelfSignature
    (Core_models.Result.impl__expect #Securedrop_protocol.Sign.t_Signature
        #Anyhow.t_Error
        (impl_JournalistClient__sign self (pubkey_bytes <: t_Slice u8)
          <:
          Core_models.Result.t_Result Securedrop_protocol.Sign.t_Signature Anyhow.t_Error)
        "Need journalist signature over their pubkeys")
    <:
    Securedrop_protocol.Sign.t_SelfSignature
  in
  let self:t_JournalistClient =
    {
      self with
      f_self_signature
      =
      Core_models.Option.Option_Some
      (Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_SelfSignature
          #FStar.Tactics.Typeclasses.solve
          self_signature)
      <:
      Core_models.Option.t_Option Securedrop_protocol.Sign.t_SelfSignature
    }
    <:
    t_JournalistClient
  in
  let longterm_enrollment_key_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistEnrollmentKeyBundle
  =
    {
      Securedrop_protocol.Keys.Journalist.f_signing_key = signing_vk;
      Securedrop_protocol.Keys.Journalist.f_public_keys = longterm_bundle;
      Securedrop_protocol.Keys.Journalist.f_self_signature = self_signature
    }
    <:
    Securedrop_protocol.Keys.Journalist.t_JournalistEnrollmentKeyBundle
  in
  let hax_temp_output:Core_models.Result.t_Result
    Securedrop_protocol.Messages.Setup.t_JournalistSetupRequest Anyhow.t_Error =
    Core_models.Result.Result_Ok
    ({ Securedrop_protocol.Messages.Setup.f_enrollment_key_bundle = longterm_enrollment_key_bundle }
      <:
      Securedrop_protocol.Messages.Setup.t_JournalistSetupRequest)
    <:
    Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupRequest
      Anyhow.t_Error
  in
  self, hax_temp_output
  <:
  (t_JournalistClient &
    Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistSetupRequest
      Anyhow.t_Error)

/// Get the journalist's verifying key
let impl_JournalistClient__verifying_key (self: t_JournalistClient)
    : Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey =
  Core_models.Option.impl__map #Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
    #Securedrop_protocol.Sign.t_VerifyingKey
    (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
        self.f_signing_key
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair)
    (fun sk ->
        let sk:Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair = sk in
        sk.Securedrop_protocol.Keys.Journalist.f_vk)

/// Generate a new ephemeral key refresh request.
/// This generates ephemeral key pairs and creates a request containing
/// the ephemeral public keys signed by the journalist's signing key.
/// Step 3.2 in the spec.
let impl_JournalistClient__create_ephemeral_key_request
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_JournalistClient)
      (rng: v_R)
    : (t_JournalistClient &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest
        Anyhow.t_Error) =
  let key_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeypairs =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistOneTimeKeypairs__generate::<\n &mut R,\n >(&mut (rng))"

  in
  match
    impl_JournalistClient__sign self
      (Securedrop_protocol.Keys.Journalist.impl_JournalistOneTimePublicKeys__into_bytes (Securedrop_protocol.Keys.Journalist.impl_JournalistOneTimeKeypairs__pubkeys
              key_bundle
            <:
            Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys)
        <:
        t_Slice u8)
    <:
    Core_models.Result.t_Result Securedrop_protocol.Sign.t_Signature Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok hoist12 ->
    let one_time_pubkey_bundle:Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle =
      {
        Securedrop_protocol.Keys.Journalist.f_public_keys
        =
        Core_models.Clone.f_clone #Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys
          #FStar.Tactics.Typeclasses.solve
          (Securedrop_protocol.Keys.Journalist.impl_JournalistOneTimeKeypairs__pubkeys key_bundle
            <:
            Securedrop_protocol.Keys.Journalist.t_JournalistOneTimePublicKeys);
        Securedrop_protocol.Keys.Journalist.f_signature = hoist12
      }
      <:
      Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
    in
    let self:t_JournalistClient =
      {
        self with
        f_one_time_keystore
        =
        Alloc.Vec.impl_1__push #Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeypairs
          #Alloc.Alloc.t_Global
          self.f_one_time_keystore
          (Core_models.Clone.f_clone #Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeypairs
              #FStar.Tactics.Typeclasses.solve
              key_bundle
            <:
            Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeypairs)
      }
      <:
      t_JournalistClient
    in
    let hax_temp_output:Core_models.Result.t_Result
      Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest Anyhow.t_Error =
      Core_models.Result.Result_Ok
      ({
          Securedrop_protocol.Messages.Setup.f_journalist_verifying_key
          =
          Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_VerifyingKey
            #FStar.Tactics.Typeclasses.solve
            (Core_models.Option.impl__expect #Securedrop_protocol.Sign.t_VerifyingKey
                (impl_JournalistClient__verifying_key self
                  <:
                  Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey)
                "Signing key should be set at this point"
              <:
              Securedrop_protocol.Sign.t_VerifyingKey);
          Securedrop_protocol.Messages.Setup.f_ephemeral_key_bundle = one_time_pubkey_bundle
        }
        <:
        Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest)
      <:
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest
        Anyhow.t_Error
    in
    self, hax_temp_output
    <:
    (t_JournalistClient &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest
        Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    self,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest
        Anyhow.t_Error)
    <:
    (t_JournalistClient &
      Core_models.Result.t_Result Securedrop_protocol.Messages.Setup.t_JournalistRefreshRequest
        Anyhow.t_Error)

/// Get the journalist's fetching key
let impl_JournalistClient__fetching_key (self: t_JournalistClient)
    : Core_models.Option.t_Option Securedrop_protocol.Primitives.X25519.t_DHPublicKey =
  Core_models.Option.impl__map #Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
    #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
    (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
        self.f_fetching_key
      <:
      Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair)
    (fun fk ->
        let fk:Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair = fk in
        fk.Securedrop_protocol.Keys.Journalist.f_public_key)

/// Get the journalist's DH-AKEM reply key.
/// Note: Messages addressed to journalist are encrypted using
/// one-time DH-AKEM keys; this key is used to send replies.
let impl_JournalistClient__dhakem_reply_key (self: t_JournalistClient)
    : Core_models.Option.t_Option Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey =
  Core_models.Option.impl__map #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
    #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
    (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
        self.f_message_send_dhakem_key
      <:
      Core_models.Option.t_Option
      Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair)
    (fun dk ->
        let dk:Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair = dk in
        dk.Securedrop_protocol.Keys.Journalist.f_public_key)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Securedrop_protocol.Client.t_Client t_JournalistClient =
  {
    f_NewsroomKey = Securedrop_protocol.Sign.t_VerifyingKey;
    f_newsroom_verifying_key_pre = (fun (self: t_JournalistClient) -> true);
    f_newsroom_verifying_key_post
    =
    (fun
        (self: t_JournalistClient)
        (out: Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey)
        ->
        true);
    f_newsroom_verifying_key
    =
    (fun (self: t_JournalistClient) ->
        Core_models.Option.impl__as_ref #Securedrop_protocol.Sign.t_VerifyingKey
          self.f_newsroom_verifying_key);
    f_set_newsroom_verifying_key_pre
    =
    (fun (self: t_JournalistClient) (key: Securedrop_protocol.Sign.t_VerifyingKey) -> true);
    f_set_newsroom_verifying_key_post
    =
    (fun
        (self: t_JournalistClient)
        (key: Securedrop_protocol.Sign.t_VerifyingKey)
        (out: t_JournalistClient)
        ->
        true);
    f_set_newsroom_verifying_key
    =
    (fun (self: t_JournalistClient) (key: Securedrop_protocol.Sign.t_VerifyingKey) ->
        let self:t_JournalistClient =
          {
            self with
            f_newsroom_verifying_key
            =
            Core_models.Option.Option_Some key
            <:
            Core_models.Option.t_Option Securedrop_protocol.Sign.t_VerifyingKey
          }
          <:
          t_JournalistClient
        in
        self);
    f_fetch_message_ids_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
        (self: t_JournalistClient)
        (e_rng: v_R)
        ->
        true);
    f_fetch_message_ids_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
        (self: t_JournalistClient)
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
      (self: t_JournalistClient)
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
let impl_2: Securedrop_protocol.Client.t_ClientPrivate t_JournalistClient =
  {
    f_fetching_private_key_pre = (fun (self: t_JournalistClient) -> true);
    f_fetching_private_key_post
    =
    (fun
        (self: t_JournalistClient)
        (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
        ->
        true);
    f_fetching_private_key
    =
    (fun (self: t_JournalistClient) ->
        Core_models.Result.Result_Ok
        (Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__into_bytes (Core_models.Clone.f_clone
                #Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
                #FStar.Tactics.Typeclasses.solve
                (Core_models.Option.impl__expect #Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
                    (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
                        self.f_fetching_key
                      <:
                      Core_models.Option.t_Option
                      Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair)
                    "Fetching key in session"
                  <:
                  Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair)
                  .Securedrop_protocol.Keys.Journalist.f_private_key
              <:
              Securedrop_protocol.Primitives.X25519.t_DHPrivateKey))
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error);
    f_message_enc_private_key_dhakem_pre = (fun (self: t_JournalistClient) -> true);
    f_message_enc_private_key_dhakem_post
    =
    (fun
        (self: t_JournalistClient)
        (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
        ->
        true);
    f_message_enc_private_key_dhakem
    =
    fun (self: t_JournalistClient) ->
      Core_models.Result.Result_Ok
      (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes (Core_models.Clone.f_clone
              #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__expect #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
                  (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
                      self.f_message_send_dhakem_key
                    <:
                    Core_models.Option.t_Option
                    Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair)
                  "Reply key in session"
                <:
                Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair)
                .Securedrop_protocol.Keys.Journalist.f_private_key
            <:
            Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey))
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  }

/// Reply to a source (step 9)
/// This is similar to Step 6 (source message submission) but from the journalist's perspective.
/// The journalist encrypts a message for a specific source using the source's public keys.
let impl_JournalistClient__reply_to_source
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_JournalistClient)
      (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (source_public_keys: Securedrop_protocol.Keys.Source.t_SourcePublicKeys)
      (source: Uuid.t_Uuid)
      (newsroom_signature: Securedrop_protocol.Sign.t_Signature)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error) =
  match
    Core_models.Option.impl__ok_or_else #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
      #Anyhow.t_Error
      (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
          self.f_message_send_dhakem_key
        <:
        Core_models.Option.t_Option
        Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair)
      (fun temp_0_ ->
          let _:Prims.unit = temp_0_ in
          let error:Anyhow.t_Error =
            Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                  (let list = ["No DH key found in session"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                    Rust_primitives.Hax.array_of_list 1 list)
                <:
                Core_models.Fmt.t_Arguments)
          in
          Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result
      Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok hoist13 ->
    let
    (journalist_dhakem_keypair:
      Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair):Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
    =
      Core_models.Clone.f_clone #Securedrop_protocol.Keys.Journalist.t_JournalistReplyClassicalKeyPair
        #FStar.Tactics.Typeclasses.solve
        hoist13
    in
    (match
        Securedrop_protocol.Client.f_get_newsroom_verifying_key #t_JournalistClient
          #FStar.Tactics.Typeclasses.solve
          self
        <:
        Core_models.Result.t_Result Securedrop_protocol.Sign.t_VerifyingKey Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok hoist14 ->
        let journalist_reply_message:Securedrop_protocol.Messages.Core.t_JournalistReplyMessage =
          {
            Securedrop_protocol.Messages.Core.f_message = message;
            Securedrop_protocol.Messages.Core.f_source = source;
            Securedrop_protocol.Messages.Core.f_journalist_sig_pk
            =
            (Core_models.Option.impl__unwrap #Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
                (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair
                    self.f_signing_key
                  <:
                  Core_models.Option.t_Option
                  Securedrop_protocol.Keys.Journalist.t_JournalistSigningKeyPair))
              .Securedrop_protocol.Keys.Journalist.f_vk;
            Securedrop_protocol.Messages.Core.f_journalist_fetch_pk
            =
            Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__unwrap #Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
                  (Core_models.Option.impl__as_ref #Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair
                      self.f_fetching_key
                    <:
                    Core_models.Option.t_Option
                    Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair)
                <:
                Securedrop_protocol.Keys.Journalist.t_JournalistFetchKeyPair)
                .Securedrop_protocol.Keys.Journalist.f_public_key;
            Securedrop_protocol.Messages.Core.f_journalist_reply_pk
            =
            Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__unwrap #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
                  (impl_JournalistClient__dhakem_reply_key self
                    <:
                    Core_models.Option.t_Option
                    Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
                <:
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey);
            Securedrop_protocol.Messages.Core.f_newsroom_signature = newsroom_signature;
            Securedrop_protocol.Messages.Core.f_newsroom_sig_pk = hoist14;
            Securedrop_protocol.Messages.Core.f_self_signature
            =
            Core_models.Clone.f_clone #Securedrop_protocol.Sign.t_SelfSignature
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Option.impl__unwrap #Securedrop_protocol.Sign.t_SelfSignature
                  (Core_models.Option.impl__as_ref #Securedrop_protocol.Sign.t_SelfSignature
                      self.f_self_signature
                    <:
                    Core_models.Option.t_Option Securedrop_protocol.Sign.t_SelfSignature)
                <:
                Securedrop_protocol.Sign.t_SelfSignature)
          }
          <:
          Securedrop_protocol.Messages.Core.t_JournalistReplyMessage
        in
        let
        (tmp0: v_R),
        (out:
          Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error) =
          Securedrop_protocol.Client.f_submit_structured_message #t_JournalistClient
            #FStar.Tactics.Typeclasses.solve
            #Securedrop_protocol.Messages.Core.t_JournalistReplyMessage #v_R self
            journalist_reply_message
            (source_public_keys.Securedrop_protocol.Keys.Source.f_message_dhakem_pk,
              source_public_keys.Securedrop_protocol.Keys.Source.f_message_pq_psk_pk
              <:
              (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey))
            source_public_keys.Securedrop_protocol.Keys.Source.f_metadata_pk
            source_public_keys.Securedrop_protocol.Keys.Source.f_fetch_pk
            journalist_dhakem_keypair.Securedrop_protocol.Keys.Journalist.f_private_key
            (Core_models.Option.impl__unwrap #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
                (Core_models.Option.impl__as_ref #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
                    (impl_JournalistClient__dhakem_reply_key self
                      <:
                      Core_models.Option.t_Option
                      Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
                  <:
                  Core_models.Option.t_Option
                  Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
              <:
              Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) rng
        in
        let rng:v_R = tmp0 in
        let hax_temp_output:Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message
          Anyhow.t_Error =
          out
        in
        rng, hax_temp_output
        <:
        (v_R &
          Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        rng,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error)
        <:
        (v_R &
          Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result Securedrop_protocol.Messages.Core.t_Message Anyhow.t_Error)
