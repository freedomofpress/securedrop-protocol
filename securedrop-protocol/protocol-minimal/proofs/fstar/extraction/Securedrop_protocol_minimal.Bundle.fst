module Securedrop_protocol_minimal.Bundle
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  let open Securedrop_protocol_minimal.Keys in
  let open Securedrop_protocol_minimal.Message in
  let open Securedrop_protocol_minimal.Primitives.X25519 in
  let open Securedrop_protocol_minimal.Sign in
  let open Securedrop_protocol_minimal.Traits in
  ()

/// Clients hold a reference to the newsroom [`VerifyingKey`](VerifyingKey)
/// of the instance they are interacting with.
class t_Client (v_Self: Type0) = {
  f_newsroom_verifying_key_pre:v_Self -> Type0;
  f_newsroom_verifying_key_post:
      v_Self ->
      Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Type0;
  f_newsroom_verifying_key:x0: v_Self
    -> Prims.Pure (Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        (f_newsroom_verifying_key_pre x0)
        (fun result -> f_newsroom_verifying_key_post x0 result);
  f_set_newsroom_verifying_key_pre:v_Self -> Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Type0;
  f_set_newsroom_verifying_key_post:
      v_Self ->
      Securedrop_protocol_minimal.Sign.t_VerifyingKey ->
      v_Self
    -> Type0;
  f_set_newsroom_verifying_key:x0: v_Self -> x1: Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Prims.Pure v_Self
        (f_set_newsroom_verifying_key_pre x0 x1)
        (fun result -> f_set_newsroom_verifying_key_post x0 x1 result)
}

/// Journalist-specific API operations.
/// Extends [`Api`] with enrollment and ephemeral key management.
class t_JournalistApi (v_Self: Type0) = {
  f_create_setup_request_pre:v_Self -> Type0;
  f_create_setup_request_post:
      v_Self ->
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest
          Anyhow.t_Error
    -> Type0;
  f_create_setup_request:x0: v_Self
    -> Prims.Pure
        (Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest
            Anyhow.t_Error)
        (f_create_setup_request_pre x0)
        (fun result -> f_create_setup_request_post x0 result);
  f_create_ephemeral_key_request_pre:v_Self -> Type0;
  f_create_ephemeral_key_request_post:
      v_Self ->
      Securedrop_protocol_minimal.Wire.Setup.t_JournalistEphemeralKeyRequest
    -> Type0;
  f_create_ephemeral_key_request:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Wire.Setup.t_JournalistEphemeralKeyRequest
        (f_create_ephemeral_key_request_pre x0)
        (fun result -> f_create_ephemeral_key_request_post x0 result)
}

/// Journalists: ingredients.
/// Journalists have a signing/verifying key, a reply key,
/// a fetch key, and a collection of one-time signed key bundles
type t_Journalist = {
  f_signing_key:Securedrop_protocol_minimal.Keys.t_KeyPair
    Securedrop_protocol_minimal.Sign.t_SigningKey Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fetch_key:Securedrop_protocol_minimal.Keys.t_KeyPair
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
  f_message_keys:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
    Alloc.Alloc.t_Global;
  f_reply_apke:Securedrop_protocol_minimal.Message.t_MessageKeyPair;
  f_self_signature:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey;
  f_signed_longterm_key_bytes:Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes;
  f_session_storage:Securedrop_protocol_minimal.Keys.t_SessionStorage
}

type t_JournalistPublicView = {
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fetch_pk:Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
  f_reply_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_signed_longterm_key_bytes:Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey;
  f_kb:(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
    Securedrop_protocol_minimal.Sign.t_Signature
    Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
}

let impl__new
      (vk: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
      (fetch: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
      (reply_apke: Securedrop_protocol_minimal.Message.t_MessagePublicKey)
      (selfsig:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey)
      (signed_longterm_key_bytes: Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes)
      (kb:
          (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))
    : t_JournalistPublicView =
  {
    f_vk = vk;
    f_fetch_pk = fetch;
    f_reply_apke_pk = reply_apke;
    f_selfsig = selfsig;
    f_signed_longterm_key_bytes = signed_longterm_key_bytes;
    f_kb = kb
  }
  <:
  t_JournalistPublicView

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1__from__journalist: Securedrop_protocol_minimal.Traits.t_UserPublic t_JournalistPublicView =
  {
    f_fetch_pk_pre = (fun (self: t_JournalistPublicView) -> true);
    f_fetch_pk_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
        ->
        true);
    f_fetch_pk = (fun (self: t_JournalistPublicView) -> self.f_fetch_pk);
    f_message_auth_pk_pre = (fun (self: t_JournalistPublicView) -> true);
    f_message_auth_pk_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey)
        ->
        true);
    f_message_auth_pk = (fun (self: t_JournalistPublicView) -> self.f_reply_apke_pk);
    f_message_metadata_pk_pre = (fun (self: t_JournalistPublicView) -> true);
    f_message_metadata_pk_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out: Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey)
        ->
        true);
    f_message_metadata_pk
    =
    (fun (self: t_JournalistPublicView) ->
        self.f_kb._1.Securedrop_protocol_minimal.Keys.f_metadata_pk);
    f_message_enc_pk_pre = (fun (self: t_JournalistPublicView) -> true);
    f_message_enc_pk_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey)
        ->
        true);
    f_message_enc_pk
    =
    fun (self: t_JournalistPublicView) -> self.f_kb._1.Securedrop_protocol_minimal.Keys.f_apke_pk
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Securedrop_protocol_minimal.Traits.t_JournalistPublic t_JournalistPublicView =
  {
    _super_i0 = FStar.Tactics.Typeclasses.solve;
    f_verifying_key_pre = (fun (self: t_JournalistPublicView) -> true);
    f_verifying_key_post
    =
    (fun (self: t_JournalistPublicView) (out: Securedrop_protocol_minimal.Sign.t_VerifyingKey) ->
        true);
    f_verifying_key = (fun (self: t_JournalistPublicView) -> self.f_vk);
    f_self_signature_pre = (fun (self: t_JournalistPublicView) -> true);
    f_self_signature_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey)
        ->
        true);
    f_self_signature = (fun (self: t_JournalistPublicView) -> self.f_selfsig);
    f_signed_keybytes_pre = (fun (self: t_JournalistPublicView) -> true);
    f_signed_keybytes_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out: Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes)
        ->
        true);
    f_signed_keybytes = (fun (self: t_JournalistPublicView) -> self.f_signed_longterm_key_bytes);
    f_ephemeral_bundle_pre = (fun (self: t_JournalistPublicView) -> true);
    f_ephemeral_bundle_post
    =
    (fun (self: t_JournalistPublicView) (out: Securedrop_protocol_minimal.Keys.t_KeyBundlePublic) ->
        true);
    f_ephemeral_bundle = (fun (self: t_JournalistPublicView) -> self.f_kb._1);
    f_ephemeral_signature_pre = (fun (self: t_JournalistPublicView) -> true);
    f_ephemeral_signature_post
    =
    (fun
        (self: t_JournalistPublicView)
        (out:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
        ->
        true);
    f_ephemeral_signature = fun (self: t_JournalistPublicView) -> self.f_kb._2
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: t_Client t_Journalist =
  {
    f_newsroom_verifying_key_pre = (fun (self: t_Journalist) -> true);
    f_newsroom_verifying_key_post
    =
    (fun
        (self: t_Journalist)
        (out: Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        ->
        true);
    f_newsroom_verifying_key
    =
    (fun (self: t_Journalist) ->
        Core_models.Option.impl__as_ref #Securedrop_protocol_minimal.Sign.t_VerifyingKey
          self.f_session_storage.Securedrop_protocol_minimal.Keys.f_nr_key);
    f_set_newsroom_verifying_key_pre
    =
    (fun (self: t_Journalist) (key: Securedrop_protocol_minimal.Sign.t_VerifyingKey) -> true);
    f_set_newsroom_verifying_key_post
    =
    (fun
        (self: t_Journalist)
        (key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        (out: t_Journalist)
        ->
        true);
    f_set_newsroom_verifying_key
    =
    fun (self: t_Journalist) (key: Securedrop_protocol_minimal.Sign.t_VerifyingKey) ->
      let self:t_Journalist =
        {
          self with
          f_session_storage
          =
          {
            self.f_session_storage with
            Securedrop_protocol_minimal.Keys.f_nr_key
            =
            Core_models.Option.Option_Some key
            <:
            Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey
          }
          <:
          Securedrop_protocol_minimal.Keys.t_SessionStorage
        }
        <:
        t_Journalist
      in
      self
  }

/// Private, common to all users, implemented for Journalists
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4: Securedrop_protocol_minimal.Traits.t_UserSecret t_Journalist =
  {
    f_num_bundles_pre = (fun (self: t_Journalist) -> true);
    f_num_bundles_post = (fun (self: t_Journalist) (out: usize) -> true);
    f_num_bundles
    =
    (fun (self: t_Journalist) ->
        Alloc.Vec.impl_1__len #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
          #Alloc.Alloc.t_Global
          self.f_message_keys);
    f_fetch_keypair_pre = (fun (self: t_Journalist) -> true);
    f_fetch_keypair_post
    =
    (fun
        (self: t_Journalist)
        (out:
          (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey))
        ->
        true);
    f_fetch_keypair
    =
    (fun (self: t_Journalist) ->
        self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_sk,
        self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_pk
        <:
        (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
          Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey));
    f_message_auth_key_pre = (fun (self: t_Journalist) -> true);
    f_message_auth_key_post
    =
    (fun (self: t_Journalist) (out: Securedrop_protocol_minimal.Message.t_MessagePrivateKey) -> true
    );
    f_message_auth_key
    =
    (fun (self: t_Journalist) ->
        Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key self.f_reply_apke);
    f_message_auth_pk_pre = (fun (self: t_Journalist) -> true);
    f_message_auth_pk_post
    =
    (fun (self: t_Journalist) (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey) -> true);
    f_message_auth_pk
    =
    (fun (self: t_Journalist) ->
        Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key self.f_reply_apke);
    f_build_message_pre
    =
    (fun (self: t_Journalist) (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_build_message_post
    =
    (fun
        (self: t_Journalist)
        (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        (out: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
        ->
        true);
    f_build_message
    =
    (fun (self: t_Journalist) (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) ->
        {
          Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key
          =
          Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32);
          Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid
          =
          Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1216);
          Securedrop_protocol_minimal.Ciphertext.f_msg = message
        }
        <:
        Securedrop_protocol_minimal.Ciphertext.t_Plaintext);
    f_keybundles_pre = (fun (self: t_Journalist) -> true);
    f_keybundles_post
    =
    (fun
        (self: t_Journalist)
        (out:
          Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global)
        ->
        true);
    f_keybundles
    =
    fun (self: t_Journalist) ->
      Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Map.t_Map
            (Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
            )
            (Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                -> Securedrop_protocol_minimal.Keys.t_MessageKeyBundle))
        #FStar.Tactics.Typeclasses.solve
        #(Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global)
        (Core_models.Iter.Traits.Iterator.f_map #(Core_models.Slice.Iter.t_Iter
              Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
            #FStar.Tactics.Typeclasses.solve
            #Securedrop_protocol_minimal.Keys.t_MessageKeyBundle
            (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                        Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                        Alloc.Alloc.t_Global)
                    #FStar.Tactics.Typeclasses.solve
                    self.f_message_keys
                  <:
                  t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
              <:
              Core_models.Slice.Iter.t_Iter
              Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
            (fun signed ->
                let signed:Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle = signed in
                signed.Securedrop_protocol_minimal.Keys.f_bundle)
          <:
          Core_models.Iter.Adapters.Map.t_Map
            (Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
            )
            (Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                -> Securedrop_protocol_minimal.Keys.t_MessageKeyBundle))
  }

let f_signed_keybundles__impl_5__extract_public_bundle
      (signed: Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
    : (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
      Securedrop_protocol_minimal.Sign.t_Signature
      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) =
  Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__public signed
      .Securedrop_protocol_minimal.Keys.f_bundle,
  signed.Securedrop_protocol_minimal.Keys.f_selfsig
  <:
  (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
    Securedrop_protocol_minimal.Sign.t_Signature
    Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5: Securedrop_protocol_minimal.Traits.t_Enrollable t_Journalist =
  {
    f_enroll_pre = (fun (self: t_Journalist) -> true);
    f_enroll_post
    =
    (fun (self: t_Journalist) (out: Securedrop_protocol_minimal.Keys.t_Enrollment) -> true);
    f_enroll
    =
    (fun (self: t_Journalist) ->
        {
          Securedrop_protocol_minimal.Keys.f_bundle
          =
          Core_models.Clone.f_clone #Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes
            #FStar.Tactics.Typeclasses.solve
            self.f_signed_longterm_key_bytes;
          Securedrop_protocol_minimal.Keys.f_selfsig = self.f_self_signature;
          Securedrop_protocol_minimal.Keys.f_keys
          =
          self.f_signing_key.Securedrop_protocol_minimal.Keys.f_pk,
          Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey
            #FStar.Tactics.Typeclasses.solve
            self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_pk,
          Core_models.Clone.f_clone #Securedrop_protocol_minimal.Message.t_MessagePublicKey
            #FStar.Tactics.Typeclasses.solve
            (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key self.f_reply_apke
              <:
              Securedrop_protocol_minimal.Message.t_MessagePublicKey)
          <:
          (Securedrop_protocol_minimal.Sign.t_VerifyingKey &
            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
            Securedrop_protocol_minimal.Message.t_MessagePublicKey)
        }
        <:
        Securedrop_protocol_minimal.Keys.t_Enrollment);
    f_signed_keybundles_pre = (fun (self: t_Journalist) -> true);
    f_signed_keybundles_post
    =
    (fun
        (self: t_Journalist)
        (out:
          Alloc.Vec.t_Vec
            (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global)
        ->
        true);
    f_signed_keybundles
    =
    (fun (self: t_Journalist) ->
        Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Map.t_Map
              (Core_models.Slice.Iter.t_Iter
                Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
              (Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                  -> (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                      Securedrop_protocol_minimal.Sign.t_Signature
                      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)))
          #FStar.Tactics.Typeclasses.solve
          #(Alloc.Vec.t_Vec
              (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global)
          (Core_models.Iter.Traits.Iterator.f_map #(Core_models.Slice.Iter.t_Iter
                Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
              #FStar.Tactics.Typeclasses.solve
              #(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
              (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                  (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                          Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                          Alloc.Alloc.t_Global)
                      #FStar.Tactics.Typeclasses.solve
                      self.f_message_keys
                    <:
                    t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
                <:
                Core_models.Slice.Iter.t_Iter
                Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
              f_signed_keybundles__impl_5__extract_public_bundle
            <:
            Core_models.Iter.Adapters.Map.t_Map
              (Core_models.Slice.Iter.t_Iter
                Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
              (Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
                  -> (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                      Securedrop_protocol_minimal.Sign.t_Signature
                      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))));
    f_signing_key_pre = (fun (self: t_Journalist) -> true);
    f_signing_key_post
    =
    (fun (self: t_Journalist) (out: Securedrop_protocol_minimal.Sign.t_VerifyingKey) -> true);
    f_signing_key
    =
    fun (self: t_Journalist) -> self.f_signing_key.Securedrop_protocol_minimal.Keys.f_pk
  }

let impl_6__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (num_keybundles: usize)
    : (v_R & t_Journalist) =
  let
  (key_bundles:
    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
    Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
      num_keybundles
  in
  let
  (tmp0: v_R),
  (out: Core_models.Result.t_Result Securedrop_protocol_minimal.Sign.t_SigningKey Anyhow.t_Error) =
    Securedrop_protocol_minimal.Sign.impl_SigningKey__new #v_R rng
  in
  let rng:v_R = tmp0 in
  let signing_key:Securedrop_protocol_minimal.Sign.t_SigningKey =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Sign.t_SigningKey
      #Anyhow.t_Error
      out
      "Signing keygen failed"
  in
  let verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
    signing_key.Securedrop_protocol_minimal.Sign.f_vk
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error) =
    Securedrop_protocol_minimal.Primitives.X25519.generate_dh_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (sk_fetch: Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey),
  (pk_fetch: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      out
      "DH Keygen (Fetch) failed"
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Message.t_MessageKeyPair Anyhow.t_Error)
  =
    Securedrop_protocol_minimal.Message.keygen #v_R rng
  in
  let rng:v_R = tmp0 in
  let reply_apke:Securedrop_protocol_minimal.Message.t_MessageKeyPair =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Message.t_MessageKeyPair
      #Anyhow.t_Error
      out
      "SD-APKE Keygen (Reply) failed"
  in
  let selfsigned_pubkeys:Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes =
    Securedrop_protocol_minimal.Keys.impl_SignedLongtermPubKeyBytes__from_keys (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key
          reply_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePublicKey)
      pk_fetch
  in
  let
  (self_signature:
    Securedrop_protocol_minimal.Sign.t_Signature
    Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey):Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey =
    Securedrop_protocol_minimal.Sign.impl_SigningKey__sign #Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey
      signing_key
      (Securedrop_protocol_minimal.Keys.impl_SignedLongtermPubKeyBytes__as_bytes selfsigned_pubkeys
        <:
        t_Slice u8)
  in
  let
  (key_bundles:
    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle Alloc.Alloc.t_Global),
  (rng: v_R) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      num_keybundles
      (fun temp_0_ temp_1_ ->
          let
          (key_bundles:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let _:usize = temp_1_ in
          true)
      (key_bundles, rng
        <:
        (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
            Alloc.Alloc.t_Global &
          v_R))
      (fun temp_0_ temp_1_ ->
          let
          (key_bundles:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let
          (tmp0: v_R),
          (out:
            Core_models.Result.t_Result Securedrop_protocol_minimal.Message.t_MessageKeyPair
              Anyhow.t_Error) =
            Securedrop_protocol_minimal.Message.keygen #v_R rng
          in
          let rng:v_R = tmp0 in
          let apke_kp:Securedrop_protocol_minimal.Message.t_MessageKeyPair =
            Core_models.Result.impl__expect #Securedrop_protocol_minimal.Message.t_MessageKeyPair
              #Anyhow.t_Error
              out
              "SD-APKE keygen (ephemeral) failed"
          in
          let
          (tmp0: v_R),
          (out:
            Core_models.Result.t_Result Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair
              Anyhow.t_Error) =
            Securedrop_protocol_minimal.Metadata.keygen #v_R rng
          in
          let rng:v_R = tmp0 in
          let metadata_kp:Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair =
            Core_models.Result.impl__expect #Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair
              #Anyhow.t_Error
              out
              "Failed to generate metadata keys"
          in
          let bundle:Securedrop_protocol_minimal.Keys.t_MessageKeyBundle =
            Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__new apke_kp metadata_kp
          in
          let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Securedrop_protocol_minimal.Keys.impl_KeyBundlePublic__as_bytes (Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__public
                  bundle
                <:
                Securedrop_protocol_minimal.Keys.t_KeyBundlePublic)
          in
          let
          (selfsig:
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey):Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey =
            Securedrop_protocol_minimal.Sign.impl_SigningKey__sign #Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey
              signing_key
              (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  pubkey_bytes
                <:
                t_Slice u8)
          in
          let key_bundles:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
            Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
              #Alloc.Alloc.t_Global
              key_bundles
              ({
                  Securedrop_protocol_minimal.Keys.f_bundle = bundle;
                  Securedrop_protocol_minimal.Keys.f_selfsig = selfsig
                }
                <:
                Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
          in
          key_bundles, rng
          <:
          (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
              Alloc.Alloc.t_Global &
            v_R))
  in
  let _:Prims.unit =
    match
      Alloc.Vec.impl_1__len #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
        #Alloc.Alloc.t_Global
        key_bundles,
      num_keybundles
      <:
      (usize & usize)
    with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let session_storage:Securedrop_protocol_minimal.Keys.t_SessionStorage =
    {
      Securedrop_protocol_minimal.Keys.f_fpf_key
      =
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey;
      Securedrop_protocol_minimal.Keys.f_nr_key
      =
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey;
      Securedrop_protocol_minimal.Keys.f_fpf_signature
      =
      Core_models.Option.Option_None
      <:
      Core_models.Option.t_Option
      (Securedrop_protocol_minimal.Sign.t_Signature Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
      )
    }
    <:
    Securedrop_protocol_minimal.Keys.t_SessionStorage
  in
  let hax_temp_output:t_Journalist =
    {
      f_signing_key
      =
      {
        Securedrop_protocol_minimal.Keys.f_sk = signing_key;
        Securedrop_protocol_minimal.Keys.f_pk = verifying_key
      }
      <:
      Securedrop_protocol_minimal.Keys.t_KeyPair Securedrop_protocol_minimal.Sign.t_SigningKey
        Securedrop_protocol_minimal.Sign.t_VerifyingKey;
      f_fetch_key
      =
      {
        Securedrop_protocol_minimal.Keys.f_sk = sk_fetch;
        Securedrop_protocol_minimal.Keys.f_pk = pk_fetch
      }
      <:
      Securedrop_protocol_minimal.Keys.t_KeyPair
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
      f_reply_apke = reply_apke;
      f_message_keys = key_bundles;
      f_self_signature = self_signature;
      f_signed_longterm_key_bytes = selfsigned_pubkeys;
      f_session_storage = session_storage
    }
    <:
    t_Journalist
  in
  rng, hax_temp_output <: (v_R & t_Journalist)

let impl_6__public (self: t_Journalist) (idx: usize) : t_JournalistPublicView =
  let kb:Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle =
    Core_models.Option.impl__expect #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
      (Core_models.Slice.impl__get #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
          #usize
          (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                  Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              self.f_message_keys
            <:
            t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
          idx
        <:
        Core_models.Option.t_Option Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
      "Bad index"
  in
  impl__new self.f_signing_key.Securedrop_protocol_minimal.Keys.f_pk
    (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey
        #FStar.Tactics.Typeclasses.solve
        self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_pk
      <:
      Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
    (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Message.t_MessagePublicKey
        #FStar.Tactics.Typeclasses.solve
        (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key self.f_reply_apke
          <:
          Securedrop_protocol_minimal.Message.t_MessagePublicKey)
      <:
      Securedrop_protocol_minimal.Message.t_MessagePublicKey)
    self.f_self_signature
    (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes
        #FStar.Tactics.Typeclasses.solve
        self.f_signed_longterm_key_bytes
      <:
      Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes)
    ((Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__public kb
            .Securedrop_protocol_minimal.Keys.f_bundle
        <:
        Securedrop_protocol_minimal.Keys.t_KeyBundlePublic),
      kb.Securedrop_protocol_minimal.Keys.f_selfsig
      <:
      (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
        Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))

/// Source fetches keys for the newsroom
/// This is the first request in step 5 of the spec.
type t_SourceNewsroomKeyRequest = | SourceNewsroomKeyRequest : t_SourceNewsroomKeyRequest

/// Newsroom returns their keys and proof of onboarding.
/// This is the first response in step 5 of the spec.
type t_SourceNewsroomKeyResponse = {
  f_newsroom_verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fpf_sig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
}

/// Source fetches journalist keys for the newsroom
/// This is part of step 5 in the spec.
/// Note: This isn't currently written down in the spec, but
/// should occur right before the server provides a long-term
/// key and an ephmeral key bundle for the journalist.
type t_SourceJournalistKeyRequest = | SourceJournalistKeyRequest : t_SourceJournalistKeyRequest

/// Server returns journalist long-term keys and ephemeral keys
/// This is the second part of step 5 in the spec.
/// Updated for 0.3 spec with new key types:
/// - ephemeral_dh_pk: MLKEM-768 for message enc PSK (one-time)
/// - ephemeral_kem_pk: DH-AKEM for message enc (one-time)
/// - ephemeral_pke_pk: XWING for metadata enc (one-time)
/// TODO: this may be split into 2 responses, one that contains
/// static keys and one that contains one-time keys
type t_SourceJournalistKeyResponse = {
  f_journalist:t_JournalistPublicView;
  f_nr_signature:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist
}

/// User (source or journalist) fetches message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchRequest =
  | MessageChallengeFetchRequest : t_MessageChallengeFetchRequest

/// Server returns encrypted message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchResponse = {
  f_count:usize;
  f_messages:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global
}

/// User fetches a specific message by ID
/// This corresponds to step 8 and 10 in the spec.
type t_MessageFetchRequest = { f_message_id:Uuid.t_Uuid }

/// Common API shared by sources and journalists. [`Api`](Api) users must provide
/// a Client implementation (local storage abstraction).
/// All users use the same API, but hax does not support default trait implementations
/// (cryspen/hax/issues/888) so the trait is defined separately.
class t_Api (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:t_Client v_Self;
  f_fetch_newsroom_keys_pre:v_Self -> Type0;
  f_fetch_newsroom_keys_post:v_Self -> t_SourceNewsroomKeyRequest -> Type0;
  f_fetch_newsroom_keys:x0: v_Self
    -> Prims.Pure t_SourceNewsroomKeyRequest
        (f_fetch_newsroom_keys_pre x0)
        (fun result -> f_fetch_newsroom_keys_post x0 result);
  f_fetch_journalist_keys_pre:v_Self -> Type0;
  f_fetch_journalist_keys_post:v_Self -> t_SourceJournalistKeyRequest -> Type0;
  f_fetch_journalist_keys:x0: v_Self
    -> Prims.Pure t_SourceJournalistKeyRequest
        (f_fetch_journalist_keys_pre x0)
        (fun result -> f_fetch_journalist_keys_post x0 result);
  f_fetch_message_ids_pre:
      #v_R: Type0 ->
      {| i0: Rand_core.t_RngCore v_R |} ->
      {| i1: Rand_core.t_CryptoRng v_R |} ->
      v_Self ->
      v_R
    -> Type0;
  f_fetch_message_ids_post:
      #v_R: Type0 ->
      {| i0: Rand_core.t_RngCore v_R |} ->
      {| i1: Rand_core.t_CryptoRng v_R |} ->
      v_Self ->
      v_R ->
      (v_R & t_MessageChallengeFetchRequest)
    -> Type0;
  f_fetch_message_ids:
      #v_R: Type0 ->
      {| i0: Rand_core.t_RngCore v_R |} ->
      {| i1: Rand_core.t_CryptoRng v_R |} ->
      x0: v_Self ->
      x1: v_R
    -> Prims.Pure (v_R & t_MessageChallengeFetchRequest)
        (f_fetch_message_ids_pre #v_R #i0 #i1 x0 x1)
        (fun result -> f_fetch_message_ids_post #v_R #i0 #i1 x0 x1 result);
  f_solve_fetch_challenges_pre:
      {| i0: Securedrop_protocol_minimal.Traits.t_UserSecret v_Self |} ->
      v_Self ->
      t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    -> Type0;
  f_solve_fetch_challenges_post:
      {| i0: Securedrop_protocol_minimal.Traits.t_UserSecret v_Self |} ->
      v_Self ->
      t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse ->
      Core_models.Result.t_Result (Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global) Anyhow.t_Error
    -> Type0;
  f_solve_fetch_challenges:
      {| i0: Securedrop_protocol_minimal.Traits.t_UserSecret v_Self |} ->
      x0: v_Self ->
      x1: t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    -> Prims.Pure
        (Core_models.Result.t_Result (Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global)
            Anyhow.t_Error)
        (f_solve_fetch_challenges_pre #i0 x0 x1)
        (fun result -> f_solve_fetch_challenges_post #i0 x0 x1 result);
  f_fetch_message_pre:v_Self -> Uuid.t_Uuid -> Type0;
  f_fetch_message_post:v_Self -> Uuid.t_Uuid -> Core_models.Option.t_Option t_MessageFetchRequest
    -> Type0;
  f_fetch_message:x0: v_Self -> x1: Uuid.t_Uuid
    -> Prims.Pure (Core_models.Option.t_Option t_MessageFetchRequest)
        (f_fetch_message_pre x0 x1)
        (fun result -> f_fetch_message_post x0 x1 result);
  f_submit_message_pre:
      #v_R: Type0 ->
      #v_S: Type0 ->
      #v_P: Type0 ->
      {| i0: Rand_core.t_RngCore v_R |} ->
      {| i1: Rand_core.t_CryptoRng v_R |} ->
      {| i2: Securedrop_protocol_minimal.Traits.t_UserSecret v_S |} ->
      {| i3: Securedrop_protocol_minimal.Traits.t_UserPublic v_P |} ->
      v_Self ->
      v_R ->
      t_Slice u8 ->
      v_S ->
      v_P
    -> Type0;
  f_submit_message_post:
      #v_R: Type0 ->
      #v_S: Type0 ->
      #v_P: Type0 ->
      {| i0: Rand_core.t_RngCore v_R |} ->
      {| i1: Rand_core.t_CryptoRng v_R |} ->
      {| i2: Securedrop_protocol_minimal.Traits.t_UserSecret v_S |} ->
      {| i3: Securedrop_protocol_minimal.Traits.t_UserPublic v_P |} ->
      v_Self ->
      v_R ->
      t_Slice u8 ->
      v_S ->
      v_P ->
      (v_R &
          Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Envelope
            Anyhow.t_Error)
    -> Type0;
  f_submit_message:
      #v_R: Type0 ->
      #v_S: Type0 ->
      #v_P: Type0 ->
      {| i0: Rand_core.t_RngCore v_R |} ->
      {| i1: Rand_core.t_CryptoRng v_R |} ->
      {| i2: Securedrop_protocol_minimal.Traits.t_UserSecret v_S |} ->
      {| i3: Securedrop_protocol_minimal.Traits.t_UserPublic v_P |} ->
      x0: v_Self ->
      x1: v_R ->
      x2: t_Slice u8 ->
      x3: v_S ->
      x4: v_P
    -> Prims.Pure
        (v_R &
          Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Envelope
            Anyhow.t_Error)
        (f_submit_message_pre #v_R #v_S #v_P #i0 #i1 #i2 #i3 x0 x1 x2 x3 x4)
        (fun result -> f_submit_message_post #v_R #v_S #v_P #i0 #i1 #i2 #i3 x0 x1 x2 x3 x4 result);
  f_handle_newsroom_key_response_pre:
      v_Self ->
      t_SourceNewsroomKeyResponse ->
      Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Type0;
  f_handle_newsroom_key_response_post:
      v_Self ->
      t_SourceNewsroomKeyResponse ->
      Securedrop_protocol_minimal.Sign.t_VerifyingKey ->
      (v_Self & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
    -> Type0;
  f_handle_newsroom_key_response:
      x0: v_Self ->
      x1: t_SourceNewsroomKeyResponse ->
      x2: Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Prims.Pure (v_Self & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
        (f_handle_newsroom_key_response_pre x0 x1 x2)
        (fun result -> f_handle_newsroom_key_response_post x0 x1 x2 result);
  f_handle_journalist_key_response_pre:
      v_Self ->
      t_SourceJournalistKeyResponse ->
      Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Type0;
  f_handle_journalist_key_response_post:
      v_Self ->
      t_SourceJournalistKeyResponse ->
      Securedrop_protocol_minimal.Sign.t_VerifyingKey ->
      Core_models.Result.t_Result Prims.unit Anyhow.t_Error
    -> Type0;
  f_handle_journalist_key_response:
      x0: v_Self ->
      x1: t_SourceJournalistKeyResponse ->
      x2: Securedrop_protocol_minimal.Sign.t_VerifyingKey
    -> Prims.Pure (Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
        (f_handle_journalist_key_response_pre x0 x1 x2)
        (fun result -> f_handle_journalist_key_response_post x0 x1 x2 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_Api v_Self|} -> i._super_i0

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_Client v_T) : t_Api v_T =
  {
    _super_i0 = FStar.Tactics.Typeclasses.solve;
    f_fetch_newsroom_keys_pre = (fun (self: v_T) -> true);
    f_fetch_newsroom_keys_post = (fun (self: v_T) (out: t_SourceNewsroomKeyRequest) -> true);
    f_fetch_newsroom_keys
    =
    (fun (self: v_T) -> SourceNewsroomKeyRequest <: t_SourceNewsroomKeyRequest);
    f_fetch_journalist_keys_pre = (fun (self: v_T) -> true);
    f_fetch_journalist_keys_post = (fun (self: v_T) (out: t_SourceJournalistKeyRequest) -> true);
    f_fetch_journalist_keys
    =
    (fun (self: v_T) -> SourceJournalistKeyRequest <: t_SourceJournalistKeyRequest);
    f_fetch_message_ids_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Rand_core.t_CryptoRng v_R)
        (self: v_T)
        (e_rng: v_R)
        ->
        true);
    f_fetch_message_ids_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Rand_core.t_CryptoRng v_R)
        (self: v_T)
        (e_rng: v_R)
        (out: (v_R & t_MessageChallengeFetchRequest))
        ->
        true);
    f_fetch_message_ids
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Rand_core.t_CryptoRng v_R)
        (self: v_T)
        (e_rng: v_R)
        ->
        let hax_temp_output:t_MessageChallengeFetchRequest =
          MessageChallengeFetchRequest <: t_MessageChallengeFetchRequest
        in
        e_rng, hax_temp_output <: (v_R & t_MessageChallengeFetchRequest));
    f_solve_fetch_challenges_pre
    =
    (fun
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i1:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_T)
        (self: v_T)
        (challenges: t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
        ->
        true);
    f_solve_fetch_challenges_post
    =
    (fun
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i1:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_T)
        (self: v_T)
        (challenges: t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
        (out:
          Core_models.Result.t_Result (Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global)
            Anyhow.t_Error)
        ->
        true);
    f_solve_fetch_challenges
    =
    (fun
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i1:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_T)
        (self: v_T)
        (challenges: t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
        ->
        Core_models.Result.Result_Ok
        (Securedrop_protocol_minimal.Encrypt_decrypt.solve_fetch_challenges #v_T self challenges)
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global)
          Anyhow.t_Error);
    f_fetch_message_pre = (fun (self: v_T) (message_id: Uuid.t_Uuid) -> true);
    f_fetch_message_post
    =
    (fun
        (self: v_T)
        (message_id: Uuid.t_Uuid)
        (out: Core_models.Option.t_Option t_MessageFetchRequest)
        ->
        true);
    f_fetch_message
    =
    (fun (self: v_T) (message_id: Uuid.t_Uuid) ->
        Core_models.Option.Option_Some ({ f_message_id = message_id } <: t_MessageFetchRequest)
        <:
        Core_models.Option.t_Option t_MessageFetchRequest);
    f_submit_message_pre
    =
    (fun
        (#v_R: Type0)
        (#v_S: Type0)
        (#v_P: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Rand_core.t_CryptoRng v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_S)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i4:
          Securedrop_protocol_minimal.Traits.t_UserPublic v_P)
        (self: v_T)
        (rng: v_R)
        (message: t_Slice u8)
        (sender: v_S)
        (recipient: v_P)
        ->
        true);
    f_submit_message_post
    =
    (fun
        (#v_R: Type0)
        (#v_S: Type0)
        (#v_P: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Rand_core.t_CryptoRng v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_S)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i4:
          Securedrop_protocol_minimal.Traits.t_UserPublic v_P)
        (self: v_T)
        (rng: v_R)
        (message: t_Slice u8)
        (sender: v_S)
        (recipient: v_P)
        (out1:
          (v_R &
            Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Envelope
              Anyhow.t_Error))
        ->
        true);
    f_submit_message
    =
    (fun
        (#v_R: Type0)
        (#v_S: Type0)
        (#v_P: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_RngCore v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Rand_core.t_CryptoRng v_R)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_S)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i4:
          Securedrop_protocol_minimal.Traits.t_UserPublic v_P)
        (self: v_T)
        (rng: v_R)
        (message: t_Slice u8)
        (sender: v_S)
        (recipient: v_P)
        ->
        let padded_message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Securedrop_protocol_minimal.Primitives.Pad.pad_message message
        in
        let plaintext:Securedrop_protocol_minimal.Ciphertext.t_Plaintext =
          Securedrop_protocol_minimal.Traits.f_build_message #v_S
            #FStar.Tactics.Typeclasses.solve
            sender
            padded_message
        in
        let (tmp0: v_R), (out: Securedrop_protocol_minimal.Ciphertext.t_Envelope) =
          Securedrop_protocol_minimal.Encrypt_decrypt.encrypt #v_R
            #v_S
            #v_P
            rng
            sender
            plaintext
            recipient
        in
        let rng:v_R = tmp0 in
        let envelope:Securedrop_protocol_minimal.Ciphertext.t_Envelope = out in
        let hax_temp_output:Core_models.Result.t_Result
          Securedrop_protocol_minimal.Ciphertext.t_Envelope Anyhow.t_Error =
          Core_models.Result.Result_Ok envelope
          <:
          Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Envelope
            Anyhow.t_Error
        in
        rng, hax_temp_output
        <:
        (v_R &
          Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Envelope
            Anyhow.t_Error));
    f_handle_newsroom_key_response_pre
    =
    (fun
        (self: v_T)
        (response: t_SourceNewsroomKeyResponse)
        (fpf_verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        ->
        true);
    f_handle_newsroom_key_response_post
    =
    (fun
        (self: v_T)
        (response: t_SourceNewsroomKeyResponse)
        (fpf_verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        (out: (v_T & Core_models.Result.t_Result Prims.unit Anyhow.t_Error))
        ->
        true);
    f_handle_newsroom_key_response
    =
    (fun
        (self: v_T)
        (response: t_SourceNewsroomKeyResponse)
        (fpf_verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        ->
        let newsroom_vk_bytes:t_Array u8 (mk_usize 32) =
          Securedrop_protocol_minimal.Sign.impl_VerifyingKey__into_bytes response
              .f_newsroom_verifying_key
        in
        match
          Core_models.Result.impl__map_err #Prims.unit
            #Anyhow.t_Error
            #Anyhow.t_Error
            (Securedrop_protocol_minimal.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
                fpf_verifying_key
                (newsroom_vk_bytes <: t_Slice u8)
                response.f_fpf_sig
              <:
              Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
            (fun temp_0_ ->
                let _:Anyhow.t_Error = temp_0_ in
                let error:Anyhow.t_Error =
                  Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                        (let list = ["invalid FPF signature on newsroom verifying key"] in
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
          let self:v_T =
            f_set_newsroom_verifying_key #v_T
              #FStar.Tactics.Typeclasses.solve
              self
              response.f_newsroom_verifying_key
          in
          let hax_temp_output:Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
            Core_models.Result.Result_Ok (() <: Prims.unit)
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error
          in
          self, hax_temp_output <: (v_T & Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
        | Core_models.Result.Result_Err err ->
          self,
          (Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
          <:
          (v_T & Core_models.Result.t_Result Prims.unit Anyhow.t_Error));
    f_handle_journalist_key_response_pre
    =
    (fun
        (self: v_T)
        (response: t_SourceJournalistKeyResponse)
        (newsroom_verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        ->
        true);
    f_handle_journalist_key_response_post
    =
    (fun
        (self: v_T)
        (response: t_SourceJournalistKeyResponse)
        (newsroom_verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        (out: Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
        ->
        true);
    f_handle_journalist_key_response
    =
    fun
      (self: v_T)
      (response: t_SourceJournalistKeyResponse)
      (newsroom_verifying_key: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
      ->
      match
        Core_models.Result.impl__map_err #Prims.unit
          #Anyhow.t_Error
          #Anyhow.t_Error
          (Securedrop_protocol_minimal.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist
              newsroom_verifying_key
              (Securedrop_protocol_minimal.Sign.impl_VerifyingKey__into_bytes (Securedrop_protocol_minimal.Traits.f_verifying_key
                      #t_JournalistPublicView
                      #FStar.Tactics.Typeclasses.solve
                      response.f_journalist
                    <:
                    Securedrop_protocol_minimal.Sign.t_VerifyingKey)
                <:
                t_Slice u8)
              response.f_nr_signature
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
          (fun temp_0_ ->
              let _:Anyhow.t_Error = temp_0_ in
              let error:Anyhow.t_Error =
                Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                      (let list = ["invalid newsroom signature on journalist signing key"] in
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
        let vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
          Securedrop_protocol_minimal.Traits.f_verifying_key #t_JournalistPublicView
            #FStar.Tactics.Typeclasses.solve
            response.f_journalist
        in
        (match
            Core_models.Result.impl__map_err #Prims.unit
              #Anyhow.t_Error
              #Anyhow.t_Error
              (Securedrop_protocol_minimal.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey
                  vk
                  (Securedrop_protocol_minimal.Keys.impl_SignedLongtermPubKeyBytes__as_bytes (Securedrop_protocol_minimal.Traits.f_signed_keybytes
                          #t_JournalistPublicView
                          #FStar.Tactics.Typeclasses.solve
                          response.f_journalist
                        <:
                        Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes)
                    <:
                    t_Slice u8)
                  (Securedrop_protocol_minimal.Traits.f_self_signature #t_JournalistPublicView
                      #FStar.Tactics.Typeclasses.solve
                      response.f_journalist
                    <:
                    Securedrop_protocol_minimal.Sign.t_Signature
                    Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey)
                <:
                Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
              (fun temp_0_ ->
                  let _:Anyhow.t_Error = temp_0_ in
                  let error:Anyhow.t_Error =
                    Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                          (let list = ["invalid journalist self-signature on long-term keys"] in
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
            (match
                Core_models.Result.impl__map_err #Prims.unit
                  #Anyhow.t_Error
                  #Anyhow.t_Error
                  (Securedrop_protocol_minimal.Sign.impl_VerifyingKey__verify #Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey
                      vk
                      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          #FStar.Tactics.Typeclasses.solve
                          (Securedrop_protocol_minimal.Keys.impl_KeyBundlePublic__as_bytes (Securedrop_protocol_minimal.Traits.f_ephemeral_bundle
                                  #t_JournalistPublicView
                                  #FStar.Tactics.Typeclasses.solve
                                  response.f_journalist
                                <:
                                Securedrop_protocol_minimal.Keys.t_KeyBundlePublic)
                            <:
                            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                        <:
                        t_Slice u8)
                      (Securedrop_protocol_minimal.Traits.f_ephemeral_signature #t_JournalistPublicView
                          #FStar.Tactics.Typeclasses.solve
                          response.f_journalist
                        <:
                        Securedrop_protocol_minimal.Sign.t_Signature
                        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
                    <:
                    Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
                  (fun temp_0_ ->
                      let _:Anyhow.t_Error = temp_0_ in
                      let error:Anyhow.t_Error =
                        Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize
                                1)
                              (let list = ["invalid journalist self-signature on one-time keys"] in
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
            Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err <: Core_models.Result.t_Result Prims.unit Anyhow.t_Error
  }

/// Provide generic implementation, restricted to implementors RestrictedApi trait and
/// the Enrollable trait. Implementors of both those will automatically be able to use
/// this generic JournalistApi implementation, but downstream crates will be unable to
/// implement RestrictedApi. Originally this was defined at the trait level
/// (`pub trait JournalistApi: Api + restricted::RestrictedApi`), but hax was unable
/// to extract the trait.
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_Api v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i1:
          Securedrop_protocol_minimal.Traits.t_Enrollable v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i2:
          Securedrop_protocol_minimal.Traits.t_RestrictedApi v_T)
    : t_JournalistApi v_T =
  {
    f_create_setup_request_pre = (fun (self: v_T) -> true);
    f_create_setup_request_post
    =
    (fun
        (self: v_T)
        (out:
          Core_models.Result.t_Result
            Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest Anyhow.t_Error)
        ->
        true);
    f_create_setup_request
    =
    (fun (self: v_T) ->
        Core_models.Result.Result_Ok
        ({
            Securedrop_protocol_minimal.Wire.Setup.f_enrollment
            =
            Securedrop_protocol_minimal.Traits.f_enroll #v_T #FStar.Tactics.Typeclasses.solve self
          }
          <:
          Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest)
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Setup.t_JournalistSetupRequest
          Anyhow.t_Error);
    f_create_ephemeral_key_request_pre = (fun (self: v_T) -> true);
    f_create_ephemeral_key_request_post
    =
    (fun
        (self: v_T)
        (out: Securedrop_protocol_minimal.Wire.Setup.t_JournalistEphemeralKeyRequest)
        ->
        true);
    f_create_ephemeral_key_request
    =
    fun (self: v_T) ->
      {
        Securedrop_protocol_minimal.Wire.Setup.f_verifying_key
        =
        Core_models.Clone.f_clone #Securedrop_protocol_minimal.Sign.t_VerifyingKey
          #FStar.Tactics.Typeclasses.solve
          (Securedrop_protocol_minimal.Traits.f_signing_key #v_T
              #FStar.Tactics.Typeclasses.solve
              self
            <:
            Securedrop_protocol_minimal.Sign.t_VerifyingKey);
        Securedrop_protocol_minimal.Wire.Setup.f_bundles
        =
        Securedrop_protocol_minimal.Traits.f_signed_keybundles #v_T
          #FStar.Tactics.Typeclasses.solve
          self
      }
      <:
      Securedrop_protocol_minimal.Wire.Setup.t_JournalistEphemeralKeyRequest
  }
