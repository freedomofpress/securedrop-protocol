module Securedrop_protocol_minimal.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Generic KeyPair
type t_KeyPair (v_SK: Type0) (v_PK: Type0) = {
  f_sk:v_SK;
  f_pk:v_PK
}

type t_SessionStorage = {
  f_fpf_key:Core_models.Option.t_Option Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey;
  f_nr_key:Core_models.Option.t_Option Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey;
  f_fpf_signature:Core_models.Option.t_Option
  (Securedrop_protocol_minimal.Schemes.Sign.t_Signature
    Securedrop_protocol_minimal.Schemes.Sign.t_FpfOnNewsroom)
}
