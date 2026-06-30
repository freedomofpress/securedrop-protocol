module Securedrop_protocol_minimal.Journalist
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

let impl_JournalistPublicView__new
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
let impl_1: Securedrop_protocol_minimal.Traits.t_UserPublic t_JournalistPublicView =
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
let impl_3: Securedrop_protocol_minimal.Api.t_Client t_Journalist =
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

#push-options "--admit_smt_queries true"

let keybundle_refs (message_keys: t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
    : Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #Securedrop_protocol_minimal.Keys.t_MessageKeyBundle ()
  in
  let out:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
              message_keys
            <:
            Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
        <:
        Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
      out
      (fun out signed ->
          let out:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle
            Alloc.Alloc.t_Global =
            out
          in
          let signed:Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle = signed in
          Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Keys.t_MessageKeyBundle
            #Alloc.Alloc.t_Global
            out
            signed.Securedrop_protocol_minimal.Keys.f_bundle
          <:
          Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global)
  in
  out

#pop-options

#push-options "--admit_smt_queries true"

let signed_keybundle_publics
      (message_keys: t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
    : Alloc.Vec.t_Vec
      (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
        Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec
    (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
      Securedrop_protocol_minimal.Sign.t_Signature
      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
        Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
      ()
  in
  let out:Alloc.Vec.t_Vec
    (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
      Securedrop_protocol_minimal.Sign.t_Signature
      Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
              message_keys
            <:
            Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
        <:
        Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
      out
      (fun out signed ->
          let out:Alloc.Vec.t_Vec
            (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global =
            out
          in
          let signed:Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle = signed in
          Alloc.Vec.impl_1__push #(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
            #Alloc.Alloc.t_Global
            out
            ((Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__public signed
                    .Securedrop_protocol_minimal.Keys.f_bundle
                <:
                Securedrop_protocol_minimal.Keys.t_KeyBundlePublic),
              signed.Securedrop_protocol_minimal.Keys.f_selfsig
              <:
              (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
                Securedrop_protocol_minimal.Sign.t_Signature
                Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))
          <:
          Alloc.Vec.t_Vec
            (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global)
  in
  out

#pop-options

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
    f_own_message_auth_pk_pre = (fun (self: t_Journalist) -> true);
    f_own_message_auth_pk_post
    =
    (fun (self: t_Journalist) (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey) -> true);
    f_own_message_auth_pk
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
      keybundle_refs (Alloc.Vec.impl_1__as_slice self.f_message_keys
          <:
          t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)
  }

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
        signed_keybundle_publics (Alloc.Vec.impl_1__as_slice self.f_message_keys
            <:
            t_Slice Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle));
    f_signing_key_pre = (fun (self: t_Journalist) -> true);
    f_signing_key_post
    =
    (fun (self: t_Journalist) (out: Securedrop_protocol_minimal.Sign.t_VerifyingKey) -> true);
    f_signing_key
    =
    fun (self: t_Journalist) -> self.f_signing_key.Securedrop_protocol_minimal.Keys.f_pk
  }

#push-options "--admit_smt_queries true"

/// Generate one ephemeral key bundle and sign its pubkeys.
let make_signed_bundle
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (signing_key: Securedrop_protocol_minimal.Sign.t_SigningKey)
    : (v_R & Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Message.t_MessageKeyPair Anyhow.t_Error)
  =
    Securedrop_protocol_minimal.Message.keygen #v_R rng
  in
  let rng:v_R = tmp0 in
  let apke_kp:Securedrop_protocol_minimal.Message.t_MessageKeyPair =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Message.t_MessageKeyPair
      #Anyhow.t_Error
      out
      "SD-APKE ephemeral keygen failed"
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
      (Alloc.Vec.impl_1__as_slice pubkey_bytes <: t_Slice u8)
  in
  let hax_temp_output:Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle =
    {
      Securedrop_protocol_minimal.Keys.f_bundle = bundle;
      Securedrop_protocol_minimal.Keys.f_selfsig = selfsig
    }
    <:
    Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle
  in
  rng, hax_temp_output <: (v_R & Securedrop_protocol_minimal.Keys.t_SignedMessageKeyBundle)

#pop-options

assume
val impl_Journalist__new':
    #v_R: Type0 ->
    {| i0: Rand_core.t_RngCore v_R |} ->
    {| i1: Rand_core.t_CryptoRng v_R |} ->
    rng: v_R ->
    num_keybundles: usize
  -> (v_R & t_Journalist)

unfold
let impl_Journalist__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
     = impl_Journalist__new' #v_R #i0 #i1

assume
val impl_Journalist__public': self: t_Journalist -> idx: usize -> t_JournalistPublicView

unfold
let impl_Journalist__public = impl_Journalist__public'

/// Generate `n` fresh signed ephemeral key bundles and retain them in memory.
/// The public halves are uploaded to the server via
/// [`create_ephemeral_key_request`](crate::api::JournalistApi::create_ephemeral_key_request).
/// The secret halves should be persisted via [`Journalist::ephemeral_bundle_bytes`].
assume
val impl_Journalist__generate_ephemeral_bundles':
    #v_R: Type0 ->
    {| i0: Rand_core.t_RngCore v_R |} ->
    {| i1: Rand_core.t_CryptoRng v_R |} ->
    self: t_Journalist ->
    rng: v_R ->
    n: usize
  -> (t_Journalist & v_R)

unfold
let impl_Journalist__generate_ephemeral_bundles
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
     = impl_Journalist__generate_ephemeral_bundles' #v_R #i0 #i1

/// Byte representation of a [`Journalist`]'s long-term keypairs, sufficient
/// to reconstruct the long-term state via
/// [`Journalist::from_long_term_bytes`].
type t_JournalistLongTermBytes = {
  f_sig_seed:t_Array u8 (mk_usize 32);
  f_fetch_sk:t_Array u8 (mk_usize 32);
  f_apke_dhakem_sk:t_Array u8 (mk_usize 32);
  f_apke_mlkem_sk:t_Array u8 (mk_usize 2400);
  f_apke_mlkem_pk:t_Array u8 (mk_usize 1184)
}

/// Extract the long-term keypairs as raw bytes, sufficient to
/// reconstruct the long-term Journalist state via
/// [`Journalist::from_long_term_bytes`].
let impl_Journalist__long_term_bytes (self: t_Journalist) : t_JournalistLongTermBytes =
  {
    f_sig_seed
    =
    Securedrop_protocol_minimal.Sign.impl_SigningKey__as_bytes self.f_signing_key
        .Securedrop_protocol_minimal.Keys.f_sk;
    f_fetch_sk
    =
    Securedrop_protocol_minimal.Primitives.X25519.impl_DHPrivateKey__as_bytes self.f_fetch_key
        .Securedrop_protocol_minimal.Keys.f_sk;
    f_apke_dhakem_sk
    =
    Securedrop_protocol_minimal.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key
          self.f_reply_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePrivateKey)
        .Securedrop_protocol_minimal.Message.f_dhakem;
    f_apke_mlkem_sk
    =
    Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PrivateKey__as_bytes (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key
          self.f_reply_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePrivateKey)
        .Securedrop_protocol_minimal.Message.f_mlkem;
    f_apke_mlkem_pk
    =
    Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key
          self.f_reply_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePublicKey)
        .Securedrop_protocol_minimal.Message.f_mlkem
  }
  <:
  t_JournalistLongTermBytes

/// Reconstruct the long-term Journalist state from raw key bytes.
assume
val impl_Journalist__from_long_term_bytes': parts: t_JournalistLongTermBytes -> t_Journalist

unfold
let impl_Journalist__from_long_term_bytes = impl_Journalist__from_long_term_bytes'

/// Serialized length of `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk`.
let impl_JournalistLongTermBytes__LEN: usize =
  (((mk_usize 32 +! mk_usize 32 <: usize) +! mk_usize 32 <: usize) +!
    Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PRIVATE_KEY_LEN
    <:
    usize) +!
  Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PUBLIC_KEY_LEN

/// Serialize as `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk`.
let impl_JournalistLongTermBytes__as_bytes (self: t_JournalistLongTermBytes)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8 impl_JournalistLongTermBytes__LEN
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_sig_seed <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_fetch_sk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_apke_dhakem_sk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_apke_mlkem_sk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_apke_mlkem_pk <: t_Slice u8)
  in
  out

/// Deserialize from `sig_seed || fetch_sk || apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk` bytes.
/// # Errors
/// Returns an error if the byte slice has the incorrect length.
let impl_JournalistLongTermBytes__from_bytes (bytes: t_Slice u8)
    : Core_models.Result.t_Result t_JournalistLongTermBytes Anyhow.t_Error =
  if (Core_models.Slice.impl__len #u8 bytes <: usize) <>. impl_JournalistLongTermBytes__LEN
  then
    let args:(usize & usize) =
      impl_JournalistLongTermBytes__LEN, Core_models.Slice.impl__len #u8 bytes <: (usize & usize)
    in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
      let list =
        [
          Core_models.Fmt.Rt.impl__new_display #usize args._1;
          Core_models.Fmt.Rt.impl__new_display #usize args._2
        ]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
      Rust_primitives.Hax.array_of_list 2 list
    in
    Core_models.Result.Result_Err
    (Anyhow.Error.impl__msg #Alloc.String.t_String
        (Core_models.Hint.must_use #Alloc.String.t_String
            (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                    (mk_usize 2)
                    (let list = ["Invalid JournalistLongTermBytes length: expected "; ", got "] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    args
                  <:
                  Core_models.Fmt.t_Arguments)
              <:
              Alloc.String.t_String)
          <:
          Alloc.String.t_String))
    <:
    Core_models.Result.t_Result t_JournalistLongTermBytes Anyhow.t_Error
  else
    let (sig_seed: t_Slice u8), (rest: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8 bytes (mk_usize 32)
    in
    let (fetch_sk: t_Slice u8), (rest: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8 rest (mk_usize 32)
    in
    let (apke_dhakem_sk: t_Slice u8), (rest: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8 rest (mk_usize 32)
    in
    let (apke_mlkem_sk: t_Slice u8), (apke_mlkem_pk: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8
        rest
        Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PRIVATE_KEY_LEN
    in
    Core_models.Result.Result_Ok
    ({
        f_sig_seed
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              sig_seed
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_fetch_sk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              fetch_sk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_apke_dhakem_sk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              apke_dhakem_sk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_apke_mlkem_sk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 2400))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 2400))
              #FStar.Tactics.Typeclasses.solve
              apke_mlkem_sk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 2400))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_apke_mlkem_pk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 1184))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 1184))
              #FStar.Tactics.Typeclasses.solve
              apke_mlkem_pk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 1184))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length"
      }
      <:
      t_JournalistLongTermBytes)
    <:
    Core_models.Result.t_Result t_JournalistLongTermBytes Anyhow.t_Error

/// Byte representation of one ephemeral key bundle's secret halves
type t_EphemeralBundleBytes = {
  f_apke_dhakem_sk:t_Array u8 (mk_usize 32);
  f_apke_mlkem_sk:t_Array u8 (mk_usize 2400);
  f_apke_mlkem_pk:t_Array u8 (mk_usize 1184);
  f_metadata_sk:t_Array u8 (mk_usize 32);
  f_metadata_pk:t_Array u8 (mk_usize 1216)
}

/// Extract the secret halves of the retained ephemeral key bundles so we can
/// reconstruct them via [`Journalist::load_ephemeral_bundles`].
/// Used by the demo.
assume
val impl_Journalist__ephemeral_bundle_bytes': self: t_Journalist
  -> Alloc.Vec.t_Vec t_EphemeralBundleBytes Alloc.Alloc.t_Global

unfold
let impl_Journalist__ephemeral_bundle_bytes = impl_Journalist__ephemeral_bundle_bytes'

/// Reconstruct ephemeral key bundles from persisted secret bytes.
/// Used by the demo
assume
val impl_Journalist__load_ephemeral_bundles':
    self: t_Journalist ->
    bundles: Alloc.Vec.t_Vec t_EphemeralBundleBytes Alloc.Alloc.t_Global
  -> t_Journalist

unfold
let impl_Journalist__load_ephemeral_bundles = impl_Journalist__load_ephemeral_bundles'

/// Serialized length of
/// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk`.
let impl_EphemeralBundleBytes__LEN: usize =
  (((mk_usize 32 +! Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PRIVATE_KEY_LEN <: usize
      ) +!
      Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PUBLIC_KEY_LEN
      <:
      usize) +!
    Securedrop_protocol_minimal.Primitives.Xwing.v_XWING_PRIVATE_KEY_LEN
    <:
    usize) +!
  Securedrop_protocol_minimal.Primitives.Xwing.v_XWING_PUBLIC_KEY_LEN

let impl_EphemeralBundleBytes__from_bundle
      (bundle: Securedrop_protocol_minimal.Keys.t_MessageKeyBundle)
    : t_EphemeralBundleBytes =
  {
    f_apke_dhakem_sk
    =
    Securedrop_protocol_minimal.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key
          bundle.Securedrop_protocol_minimal.Keys.f_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePrivateKey)
        .Securedrop_protocol_minimal.Message.f_dhakem;
    f_apke_mlkem_sk
    =
    Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PrivateKey__as_bytes (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key
          bundle.Securedrop_protocol_minimal.Keys.f_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePrivateKey)
        .Securedrop_protocol_minimal.Message.f_mlkem;
    f_apke_mlkem_pk
    =
    Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key
          bundle.Securedrop_protocol_minimal.Keys.f_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePublicKey)
        .Securedrop_protocol_minimal.Message.f_mlkem;
    f_metadata_sk
    =
    Securedrop_protocol_minimal.Metadata.impl_MetadataKeyPair__secret_bytes bundle
        .Securedrop_protocol_minimal.Keys.f_metadata_kp;
    f_metadata_pk
    =
    Securedrop_protocol_minimal.Metadata.impl_MetadataKeyPair__public_bytes bundle
        .Securedrop_protocol_minimal.Keys.f_metadata_kp
  }
  <:
  t_EphemeralBundleBytes

assume
val impl_EphemeralBundleBytes__into_bundle': self: t_EphemeralBundleBytes
  -> Securedrop_protocol_minimal.Keys.t_MessageKeyBundle

unfold
let impl_EphemeralBundleBytes__into_bundle = impl_EphemeralBundleBytes__into_bundle'

/// Serialize as
/// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk`.
let impl_EphemeralBundleBytes__as_bytes (self: t_EphemeralBundleBytes)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8 impl_EphemeralBundleBytes__LEN
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_apke_dhakem_sk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_apke_mlkem_sk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_apke_mlkem_pk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_metadata_sk <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (self.f_metadata_pk <: t_Slice u8)
  in
  out

/// Deserialize from
/// `apke_dhakem_sk || apke_mlkem_sk || apke_mlkem_pk || metadata_sk || metadata_pk` bytes.
/// # Errors
/// Returns an error if the byte slice has the incorrect length.
let impl_EphemeralBundleBytes__from_bytes (bytes: t_Slice u8)
    : Core_models.Result.t_Result t_EphemeralBundleBytes Anyhow.t_Error =
  if (Core_models.Slice.impl__len #u8 bytes <: usize) <>. impl_EphemeralBundleBytes__LEN
  then
    let args:(usize & usize) =
      impl_EphemeralBundleBytes__LEN, Core_models.Slice.impl__len #u8 bytes <: (usize & usize)
    in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
      let list =
        [
          Core_models.Fmt.Rt.impl__new_display #usize args._1;
          Core_models.Fmt.Rt.impl__new_display #usize args._2
        ]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
      Rust_primitives.Hax.array_of_list 2 list
    in
    Core_models.Result.Result_Err
    (Anyhow.Error.impl__msg #Alloc.String.t_String
        (Core_models.Hint.must_use #Alloc.String.t_String
            (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                    (mk_usize 2)
                    (let list = ["Invalid EphemeralBundleBytes length: expected "; ", got "] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    args
                  <:
                  Core_models.Fmt.t_Arguments)
              <:
              Alloc.String.t_String)
          <:
          Alloc.String.t_String))
    <:
    Core_models.Result.t_Result t_EphemeralBundleBytes Anyhow.t_Error
  else
    let (apke_dhakem_sk: t_Slice u8), (rest: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8 bytes (mk_usize 32)
    in
    let (apke_mlkem_sk: t_Slice u8), (rest: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8
        rest
        Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PRIVATE_KEY_LEN
    in
    let (apke_mlkem_pk: t_Slice u8), (rest: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8
        rest
        Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PUBLIC_KEY_LEN
    in
    let (metadata_sk: t_Slice u8), (metadata_pk: t_Slice u8) =
      Core_models.Slice.impl__split_at #u8
        rest
        Securedrop_protocol_minimal.Primitives.Xwing.v_XWING_PRIVATE_KEY_LEN
    in
    Core_models.Result.Result_Ok
    ({
        f_apke_dhakem_sk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              apke_dhakem_sk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_apke_mlkem_sk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 2400))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 2400))
              #FStar.Tactics.Typeclasses.solve
              apke_mlkem_sk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 2400))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_apke_mlkem_pk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 1184))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 1184))
              #FStar.Tactics.Typeclasses.solve
              apke_mlkem_pk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 1184))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_metadata_sk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              metadata_sk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length";
        f_metadata_pk
        =
        Core_models.Result.impl__expect #(t_Array u8 (mk_usize 1216))
          #Core_models.Array.t_TryFromSliceError
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 1216))
              #FStar.Tactics.Typeclasses.solve
              metadata_pk
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 1216))
              Core_models.Array.t_TryFromSliceError)
          "wrong checked length"
      }
      <:
      t_EphemeralBundleBytes)
    <:
    Core_models.Result.t_Result t_EphemeralBundleBytes Anyhow.t_Error
