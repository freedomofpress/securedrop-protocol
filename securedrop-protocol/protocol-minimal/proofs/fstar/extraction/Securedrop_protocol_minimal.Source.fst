module Securedrop_protocol_minimal.Source
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Argon2.Error in
  let open Blake2 in
  let open Block_buffer in
  let open Digest in
  let open Digest.Core_api in
  let open Digest.Core_api.Ct_variable in
  let open Digest.Core_api.Wrapper in
  let open Digest.Digest in
  let open Generic_array in
  let open Generic_array.Impls in
  let open Rand_core in
  let open Securedrop_protocol_minimal.Message in
  let open Typenum in
  let open Typenum.Bit in
  let open Typenum.Marker_traits in
  let open Typenum.Private in
  let open Typenum.Type_operators in
  let open Typenum.Uint in
  ()

/// Fixed public salt for Argon2id. Argon2id requires a salt; since source
/// keys must be deterministic from the passphrase alone, we use a fixed
/// application-specific value rather than a random one.
let v_SOURCE_PBKDF_SALT: t_Slice u8 =
  (let list =
      [
        mk_u8 115; mk_u8 101; mk_u8 99; mk_u8 117; mk_u8 114; mk_u8 101; mk_u8 100; mk_u8 114;
        mk_u8 111; mk_u8 112; mk_u8 45; mk_u8 115; mk_u8 111; mk_u8 117; mk_u8 114; mk_u8 99;
        mk_u8 101; mk_u8 45; mk_u8 118; mk_u8 49
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 20);
    Rust_primitives.Hax.array_of_list 20 list)
  <:
  t_Slice u8

/// A source and their long-term key material (step 4).
/// A source's keys are fully determined by their passphrase: the fetch key,
/// APKE key, and PKE key are all derived from a master key via Argon2id and
/// a domain-separated KDF. Returning sources reconstruct the same keys by
/// calling [`Source::from_passphrase`] with the same passphrase.
type t_Source = {
  f_fetch_key:Securedrop_protocol_minimal.Keys.t_KeyPair
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
  f_message_keys:Securedrop_protocol_minimal.Keys.t_MessageKeyBundle;
  f_passphrase:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_session:Securedrop_protocol_minimal.Keys.t_SessionStorage
}

/// The public key material of a source, used by journalists to send replies.
type t_SourcePublicView = {
  f_fetch_pk:Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
  f_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_message_pks:Securedrop_protocol_minimal.Keys.t_KeyBundlePublic
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_SourcePublicView

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_SourcePublicView =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Securedrop_protocol_minimal.Traits.t_UserPublic t_SourcePublicView =
  {
    f_fetch_pk_pre = (fun (self: t_SourcePublicView) -> true);
    f_fetch_pk_post
    =
    (fun
        (self: t_SourcePublicView)
        (out: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
        ->
        true);
    f_fetch_pk = (fun (self: t_SourcePublicView) -> self.f_fetch_pk);
    f_message_auth_pk_pre = (fun (self: t_SourcePublicView) -> true);
    f_message_auth_pk_post
    =
    (fun (self: t_SourcePublicView) (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey) ->
        true);
    f_message_auth_pk = (fun (self: t_SourcePublicView) -> self.f_apke_pk);
    f_message_metadata_pk_pre = (fun (self: t_SourcePublicView) -> true);
    f_message_metadata_pk_post
    =
    (fun
        (self: t_SourcePublicView)
        (out: Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey)
        ->
        true);
    f_message_metadata_pk
    =
    (fun (self: t_SourcePublicView) ->
        self.f_message_pks.Securedrop_protocol_minimal.Keys.f_metadata_pk);
    f_message_enc_pk_pre = (fun (self: t_SourcePublicView) -> true);
    f_message_enc_pk_post
    =
    (fun (self: t_SourcePublicView) (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey) ->
        true);
    f_message_enc_pk
    =
    fun (self: t_SourcePublicView) -> self.f_message_pks.Securedrop_protocol_minimal.Keys.f_apke_pk
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Securedrop_protocol_minimal.Api.t_Client t_Source =
  {
    f_newsroom_verifying_key_pre = (fun (self: t_Source) -> true);
    f_newsroom_verifying_key_post
    =
    (fun
        (self: t_Source)
        (out: Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey)
        ->
        true);
    f_newsroom_verifying_key
    =
    (fun (self: t_Source) ->
        Core_models.Option.impl__as_ref #Securedrop_protocol_minimal.Sign.t_VerifyingKey
          self.f_session.Securedrop_protocol_minimal.Keys.f_nr_key);
    f_set_newsroom_verifying_key_pre
    =
    (fun (self: t_Source) (key: Securedrop_protocol_minimal.Sign.t_VerifyingKey) -> true);
    f_set_newsroom_verifying_key_post
    =
    (fun (self: t_Source) (key: Securedrop_protocol_minimal.Sign.t_VerifyingKey) (out: t_Source) ->
        true);
    f_set_newsroom_verifying_key
    =
    fun (self: t_Source) (key: Securedrop_protocol_minimal.Sign.t_VerifyingKey) ->
      let self:t_Source =
        {
          self with
          f_session
          =
          {
            self.f_session with
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
        t_Source
      in
      self
  }

/// Private, common to all users, implemented for sources
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Securedrop_protocol_minimal.Traits.t_UserSecret t_Source =
  {
    f_num_bundles_pre = (fun (self: t_Source) -> true);
    f_num_bundles_post = (fun (self: t_Source) (out: usize) -> true);
    f_num_bundles = (fun (self: t_Source) -> mk_usize 1);
    f_fetch_keypair_pre = (fun (self: t_Source) -> true);
    f_fetch_keypair_post
    =
    (fun
        (self: t_Source)
        (out:
          (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey))
        ->
        true);
    f_fetch_keypair
    =
    (fun (self: t_Source) ->
        self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_sk,
        self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_pk
        <:
        (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
          Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey));
    f_message_auth_key_pre = (fun (self: t_Source) -> true);
    f_message_auth_key_post
    =
    (fun (self: t_Source) (out: Securedrop_protocol_minimal.Message.t_MessagePrivateKey) -> true);
    f_message_auth_key
    =
    (fun (self: t_Source) ->
        Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key self.f_message_keys
            .Securedrop_protocol_minimal.Keys.f_apke);
    f_message_auth_pk_pre = (fun (self: t_Source) -> true);
    f_message_auth_pk_post
    =
    (fun (self: t_Source) (out: Securedrop_protocol_minimal.Message.t_MessagePublicKey) -> true);
    f_message_auth_pk
    =
    (fun (self: t_Source) ->
        Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key self.f_message_keys
            .Securedrop_protocol_minimal.Keys.f_apke);
    f_build_message_pre
    =
    (fun (self: t_Source) (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_build_message_post
    =
    (fun
        (self: t_Source)
        (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        (out: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
        ->
        true);
    f_build_message
    =
    (fun (self: t_Source) (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) ->
        let fetch_pk:t_Array u8 (mk_usize 32) =
          Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
        in
        let fetch_pk:t_Array u8 (mk_usize 32) =
          Core_models.Slice.impl__copy_from_slice #u8
            fetch_pk
            (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__into_bytes self
                  .f_fetch_key
                  .Securedrop_protocol_minimal.Keys.f_pk
              <:
              t_Slice u8)
        in
        let reply_key_pq_hybrid:t_Array u8 (mk_usize 1216) =
          Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1216)
        in
        let reply_key_pq_hybrid:t_Array u8 (mk_usize 1216) =
          Core_models.Slice.impl__copy_from_slice #u8
            reply_key_pq_hybrid
            (Securedrop_protocol_minimal.Metadata.impl_MetadataPublicKey__as_bytes (Securedrop_protocol_minimal.Metadata.impl_MetadataKeyPair__public_key
                    self.f_message_keys.Securedrop_protocol_minimal.Keys.f_metadata_kp
                  <:
                  Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey)
              <:
              t_Slice u8)
        in
        {
          Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key = fetch_pk;
          Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid = reply_key_pq_hybrid;
          Securedrop_protocol_minimal.Ciphertext.f_msg = message
        }
        <:
        Securedrop_protocol_minimal.Ciphertext.t_Plaintext);
    f_keybundles_pre = (fun (self: t_Source) -> true);
    f_keybundles_post
    =
    (fun
        (self: t_Source)
        (out:
          Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global)
        ->
        true);
    f_keybundles
    =
    fun (self: t_Source) ->
      Alloc.Slice.impl__into_vec #Securedrop_protocol_minimal.Keys.t_MessageKeyBundle
        #Alloc.Alloc.t_Global
        (Rust_primitives.unsize (Rust_primitives.Hax.box_new (let list = [self.f_message_keys] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list)
              <:
              Alloc.Boxed.t_Box
                (t_Array Securedrop_protocol_minimal.Keys.t_MessageKeyBundle (mk_usize 1))
                Alloc.Alloc.t_Global)
          <:
          Alloc.Boxed.t_Box (t_Slice Securedrop_protocol_minimal.Keys.t_MessageKeyBundle)
            Alloc.Alloc.t_Global)
  }

/// Returns the source's passphrase.
/// # Security
/// The passphrase is the root secret from which all source keys are
/// derived. It MUST be stored and transmitted only over secure channels.
let impl_Source__passphrase (self: t_Source) : t_Slice u8 =
  Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_passphrase

/// Derive the master key from a passphrase using Argon2id (step 4).
/// Uses a fixed, public, domain-specific salt. The security of the master
/// key rests entirely on the entropy of the passphrase.
let impl_Source__derive_master_key (passphrase: t_Slice u8) : t_Array u8 (mk_usize 64) =
  let params:Argon2.Params.t_Params =
    Core_models.Result.impl__expect #Argon2.Params.t_Params
      #Argon2.Error.t_Error
      (Argon2.Params.impl_Params__new (mk_u32 19456)
          (mk_u32 2)
          (mk_u32 1)
          (Core_models.Option.Option_Some (mk_usize 64) <: Core_models.Option.t_Option usize)
        <:
        Core_models.Result.t_Result Argon2.Params.t_Params Argon2.Error.t_Error)
      "valid Argon2id params"
  in
  let argon2:Argon2.t_Argon2 =
    Argon2.impl_2__new (Argon2.Algorithm.Algorithm_Argon2id <: Argon2.Algorithm.t_Algorithm)
      (Argon2.Version.Version_V0x13 <: Argon2.Version.t_Version)
      params
  in
  let mk:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let
  (tmp0: t_Array u8 (mk_usize 64)),
  (out: Core_models.Result.t_Result Prims.unit Argon2.Error.t_Error) =
    Argon2.impl_2__hash_password_into argon2 passphrase v_SOURCE_PBKDF_SALT mk
  in
  let mk:t_Array u8 (mk_usize 64) = tmp0 in
  let _:Prims.unit =
    Core_models.Result.impl__expect #Prims.unit
      #Argon2.Error.t_Error
      out
      "Argon2id master key derivation failed"
  in
  mk

/// Reconstruct source keys from a passphrase (step 4).
/// Derives a master key via [`Source::derive_master_key`], then derives
/// each private key from the master key using a domain-separated KDF.
let impl_Source__from_passphrase (passphrase: t_Slice u8) : t_Source =
  let mk:t_Array u8 (mk_usize 64) = impl_Source__derive_master_key passphrase in
  let fetch_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let fetch_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 14))
      fetch_hasher
      (let list =
          [
            mk_u8 115; mk_u8 111; mk_u8 117; mk_u8 114; mk_u8 99; mk_u8 101; mk_u8 102; mk_u8 101;
            mk_u8 116; mk_u8 99; mk_u8 104; mk_u8 107; mk_u8 101; mk_u8 121
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 14);
        Rust_primitives.Hax.array_of_list 14 list)
  in
  let fetch_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 64))
      fetch_hasher
      mk
  in
  let fetch_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      fetch_hasher
  in
  let dh_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let dh_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 16))
      dh_hasher
      (let list =
          [
            mk_u8 115; mk_u8 111; mk_u8 117; mk_u8 114; mk_u8 99; mk_u8 101; mk_u8 65; mk_u8 80;
            mk_u8 75; mk_u8 69; mk_u8 107; mk_u8 101; mk_u8 121; mk_u8 45; mk_u8 100; mk_u8 104
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 16);
        Rust_primitives.Hax.array_of_list 16 list)
  in
  let dh_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 64))
      dh_hasher
      mk
  in
  let dh_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      dh_hasher
  in
  let kem_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let kem_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 19))
      kem_hasher
      (let list =
          [
            mk_u8 115; mk_u8 111; mk_u8 117; mk_u8 114; mk_u8 99; mk_u8 101; mk_u8 65; mk_u8 80;
            mk_u8 75; mk_u8 69; mk_u8 107; mk_u8 101; mk_u8 121; mk_u8 45; mk_u8 109; mk_u8 108;
            mk_u8 107; mk_u8 101; mk_u8 109
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 19);
        Rust_primitives.Hax.array_of_list 19 list)
  in
  let kem_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 64))
      kem_hasher
      mk
  in
  let kem_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Typenum.Bit.t_B0) Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      kem_hasher
  in
  let pke_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let pke_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 12))
      pke_hasher
      (let list =
          [
            mk_u8 115; mk_u8 111; mk_u8 117; mk_u8 114; mk_u8 99; mk_u8 101; mk_u8 80; mk_u8 75;
            mk_u8 69; mk_u8 107; mk_u8 101; mk_u8 121
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 12);
        Rust_primitives.Hax.array_of_list 12 list)
  in
  let pke_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 64))
      pke_hasher
      mk
  in
  let pke_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      pke_hasher
  in
  let fetch_sk, fetch_pk:(Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Primitives.X25519.deterministic_dh_keygen (Core_models.Convert.f_into
              #(Generic_array.t_GenericArray u8
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0))
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              fetch_result
            <:
            t_Array u8 (mk_usize 32))
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "Need Fetch keygen"
  in
  let message_kp:Securedrop_protocol_minimal.Message.t_MessageKeyPair =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Message.t_MessageKeyPair
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Message.deterministic_keygen (Core_models.Convert.f_into #(Generic_array.t_GenericArray
                  u8
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0))
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              dh_result
            <:
            t_Array u8 (mk_usize 32))
          (Core_models.Convert.f_into #(Generic_array.t_GenericArray u8
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt
                                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1
                                          ) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0))
              #(t_Array u8 (mk_usize 64))
              #FStar.Tactics.Typeclasses.solve
              kem_result
            <:
            t_Array u8 (mk_usize 64))
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Message.t_MessageKeyPair
          Anyhow.t_Error)
      "Need SD-APKE keygen"
  in
  let metadata_kp:Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Metadata.deterministic_keygen (Core_models.Convert.f_into #(Generic_array.t_GenericArray
                  u8
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0))
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              pke_result
            <:
            t_Array u8 (mk_usize 32))
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair
          Anyhow.t_Error)
      "Need X-Wing keygen"
  in
  let session:Securedrop_protocol_minimal.Keys.t_SessionStorage =
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
  {
    f_fetch_key
    =
    {
      Securedrop_protocol_minimal.Keys.f_sk = fetch_sk;
      Securedrop_protocol_minimal.Keys.f_pk = fetch_pk
    }
    <:
    Securedrop_protocol_minimal.Keys.t_KeyPair
      Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey
      Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
    f_message_keys
    =
    Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__new message_kp metadata_kp;
    f_passphrase = Alloc.Slice.impl__to_vec #u8 passphrase;
    f_session = session
  }
  <:
  t_Source

/// Create a new source with a randomly generated passphrase.
/// TODO / For testing only - in production the passphrase must be a mnemonic
/// of sufficient entropy generated and displayed to the source.
let impl_Source__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_Source =
  let passphrase:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng passphrase
  in
  let rng:v_R = tmp0 in
  let passphrase:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  impl_Source__from_passphrase (passphrase <: t_Slice u8)

/// Returns the public key material for this source.
let impl_Source__public (self: t_Source) : t_SourcePublicView =
  {
    f_fetch_pk = self.f_fetch_key.Securedrop_protocol_minimal.Keys.f_pk;
    f_apke_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol_minimal.Message.t_MessagePublicKey
      #FStar.Tactics.Typeclasses.solve
      (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key self.f_message_keys
            .Securedrop_protocol_minimal.Keys.f_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePublicKey);
    f_message_pks
    =
    Securedrop_protocol_minimal.Keys.impl_MessageKeyBundle__public self.f_message_keys
  }
  <:
  t_SourcePublicView
