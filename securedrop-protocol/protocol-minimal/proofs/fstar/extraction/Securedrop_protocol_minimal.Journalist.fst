module Securedrop_protocol_minimal.Journalist
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol_minimal.Keys in
  let open Securedrop_protocol_minimal.Message in
  let open Securedrop_protocol_minimal.Primitives.X25519 in
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
