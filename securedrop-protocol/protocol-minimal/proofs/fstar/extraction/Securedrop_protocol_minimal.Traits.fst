module Securedrop_protocol_minimal.Traits
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Sealed in
  ()

/// Users have the following (public traits) in common:
/// They expose a fetch pubkey, a message auth pubkey
/// (implicit authentication),
/// and a collection of KeyBundles (tuples of keys - a keybundle contains
/// all the key material required to send a message to a given user).
/// A Source has a KeyBundle collection of size 1.
/// A Journalist has KeyBundle collection of size > 1.
/// Some users (Sources) use a key from their message bundle as
/// their message auth key.
class t_UserPublic (v_Self: Type0) = {
  f_fetch_pk_pre:v_Self -> Type0;
  f_fetch_pk_post:v_Self -> Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey -> Type0;
  f_fetch_pk:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey
        (f_fetch_pk_pre x0)
        (fun result -> f_fetch_pk_post x0 result);
  f_message_auth_pk_pre:v_Self -> Type0;
  f_message_auth_pk_post:v_Self -> Securedrop_protocol_minimal.Message.t_MessagePublicKey -> Type0;
  f_message_auth_pk:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Message.t_MessagePublicKey
        (f_message_auth_pk_pre x0)
        (fun result -> f_message_auth_pk_post x0 result);
  f_message_metadata_pk_pre:v_Self -> Type0;
  f_message_metadata_pk_post:v_Self -> Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
    -> Type0;
  f_message_metadata_pk:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
        (f_message_metadata_pk_pre x0)
        (fun result -> f_message_metadata_pk_post x0 result);
  f_message_enc_pk_pre:v_Self -> Type0;
  f_message_enc_pk_post:v_Self -> Securedrop_protocol_minimal.Message.t_MessagePublicKey -> Type0;
  f_message_enc_pk:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Message.t_MessagePublicKey
        (f_message_enc_pk_pre x0)
        (fun result -> f_message_enc_pk_post x0 result)
}

class t_JournalistPublic (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:t_UserPublic v_Self;
  f_verifying_key_pre:v_Self -> Type0;
  f_verifying_key_post:v_Self -> Securedrop_protocol_minimal.Sign.t_VerifyingKey -> Type0;
  f_verifying_key:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Sign.t_VerifyingKey
        (f_verifying_key_pre x0)
        (fun result -> f_verifying_key_post x0 result);
  f_self_signature_pre:v_Self -> Type0;
  f_self_signature_post:
      v_Self ->
      Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey
    -> Type0;
  f_self_signature:x0: v_Self
    -> Prims.Pure
        (Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey)
        (f_self_signature_pre x0)
        (fun result -> f_self_signature_post x0 result);
  f_signed_keybytes_pre:v_Self -> Type0;
  f_signed_keybytes_post:v_Self -> Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes
    -> Type0;
  f_signed_keybytes:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes
        (f_signed_keybytes_pre x0)
        (fun result -> f_signed_keybytes_post x0 result);
  f_ephemeral_bundle_pre:v_Self -> Type0;
  f_ephemeral_bundle_post:v_Self -> Securedrop_protocol_minimal.Keys.t_KeyBundlePublic -> Type0;
  f_ephemeral_bundle:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Keys.t_KeyBundlePublic
        (f_ephemeral_bundle_pre x0)
        (fun result -> f_ephemeral_bundle_post x0 result);
  f_ephemeral_signature_pre:v_Self -> Type0;
  f_ephemeral_signature_post:
      v_Self ->
      Securedrop_protocol_minimal.Sign.t_Signature
        Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey
    -> Type0;
  f_ephemeral_signature:x0: v_Self
    -> Prims.Pure
        (Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
        (f_ephemeral_signature_pre x0)
        (fun result -> f_ephemeral_signature_post x0 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_JournalistPublic v_Self|} -> i._super_i0

class t_Enrollable (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:Securedrop_protocol_minimal.Sealed.t_Sealed
  v_Self;
  f_signing_key_pre:v_Self -> Type0;
  f_signing_key_post:v_Self -> Securedrop_protocol_minimal.Sign.t_VerifyingKey -> Type0;
  f_signing_key:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Sign.t_VerifyingKey
        (f_signing_key_pre x0)
        (fun result -> f_signing_key_post x0 result);
  f_enroll_pre:v_Self -> Type0;
  f_enroll_post:v_Self -> Securedrop_protocol_minimal.Keys.t_Enrollment -> Type0;
  f_enroll:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Keys.t_Enrollment
        (f_enroll_pre x0)
        (fun result -> f_enroll_post x0 result);
  f_signed_keybundles_pre:v_Self -> Type0;
  f_signed_keybundles_post:
      v_Self ->
      Alloc.Vec.t_Vec
          (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global
    -> Type0;
  f_signed_keybundles:x0: v_Self
    -> Prims.Pure
        (Alloc.Vec.t_Vec
            (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
              Securedrop_protocol_minimal.Sign.t_Signature
              Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey) Alloc.Alloc.t_Global)
        (f_signed_keybundles_pre x0)
        (fun result -> f_signed_keybundles_post x0 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_Enrollable v_Self|} -> i._super_i0

/// Users have the following (secret traits) in common:
/// They have a fetching keypair used to retrieve messages;
/// They have a message authentication keypair used to implicitly
/// authenticate their messages (via DH-AKEM);
/// They can index a KeyBundle (tuple) and use it to attempt to
/// decrypt a message.
class t_UserSecret (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:Securedrop_protocol_minimal.Sealed.t_Sealed
  v_Self;
  f_num_bundles_pre:v_Self -> Type0;
  f_num_bundles_post:v_Self -> usize -> Type0;
  f_num_bundles:x0: v_Self
    -> Prims.Pure usize (f_num_bundles_pre x0) (fun result -> f_num_bundles_post x0 result);
  f_fetch_keypair_pre:v_Self -> Type0;
  f_fetch_keypair_post:
      v_Self ->
      (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
          Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
    -> Type0;
  f_fetch_keypair:x0: v_Self
    -> Prims.Pure
        (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
          Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
        (f_fetch_keypair_pre x0)
        (fun result -> f_fetch_keypair_post x0 result);
  f_message_auth_key_pre:v_Self -> Type0;
  f_message_auth_key_post:v_Self -> Securedrop_protocol_minimal.Message.t_MessagePrivateKey -> Type0;
  f_message_auth_key:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Message.t_MessagePrivateKey
        (f_message_auth_key_pre x0)
        (fun result -> f_message_auth_key_post x0 result);
  f_message_auth_pk_pre:v_Self -> Type0;
  f_message_auth_pk_post:v_Self -> Securedrop_protocol_minimal.Message.t_MessagePublicKey -> Type0;
  f_message_auth_pk:x0: v_Self
    -> Prims.Pure Securedrop_protocol_minimal.Message.t_MessagePublicKey
        (f_message_auth_pk_pre x0)
        (fun result -> f_message_auth_pk_post x0 result);
  f_build_message_pre:v_Self -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> Type0;
  f_build_message_post:
      v_Self ->
      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global ->
      Securedrop_protocol_minimal.Ciphertext.t_Plaintext
    -> Type0;
  f_build_message:x0: v_Self -> x1: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
    -> Prims.Pure Securedrop_protocol_minimal.Ciphertext.t_Plaintext
        (f_build_message_pre x0 x1)
        (fun result -> f_build_message_post x0 x1 result);
  f_keybundles_pre:v_Self -> Type0;
  f_keybundles_post:
      v_Self ->
      Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global
    -> Type0;
  f_keybundles:x0: v_Self
    -> Prims.Pure
        (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle Alloc.Alloc.t_Global)
        (f_keybundles_pre x0)
        (fun result -> f_keybundles_post x0 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_UserSecret v_Self|} -> i._super_i0

class t_RestrictedApi (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:Securedrop_protocol_minimal.Sealed.t_Sealed
  v_Self
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_RestrictedApi v_Self|} -> i._super_i0
