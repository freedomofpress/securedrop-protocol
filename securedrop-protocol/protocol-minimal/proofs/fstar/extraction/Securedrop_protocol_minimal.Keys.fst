module Securedrop_protocol_minimal.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Generic KeyPair
type t_KeyPair (v_SK: Type0) (v_PK: Type0) = {
  f_sk:v_SK;
  f_pk:v_PK
}

/// The public keys that make up one ephemeral key bundle
type t_KeyBundlePublic = {
  f_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_metadata_pk:Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
}

type t_MessageKeyBundle = {
  f_apke:Securedrop_protocol_minimal.Message.t_MessageKeyPair;
  f_metadata_kp:Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair
}

type t_SignedLongtermPubKeyBytes =
  | SignedLongtermPubKeyBytes : t_Array u8 (mk_usize 1248) -> t_SignedLongtermPubKeyBytes

type t_SessionStorage = {
  f_fpf_key:Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_nr_key:Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fpf_signature:Core_models.Option.t_Option
  (Securedrop_protocol_minimal.Sign.t_Signature Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
}
