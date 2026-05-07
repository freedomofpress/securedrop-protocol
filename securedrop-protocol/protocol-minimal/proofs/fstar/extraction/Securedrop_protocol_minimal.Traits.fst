module Securedrop_protocol_minimal.Traits
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

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
