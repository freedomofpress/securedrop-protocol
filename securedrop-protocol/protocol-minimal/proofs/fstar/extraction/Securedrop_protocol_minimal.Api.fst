module Securedrop_protocol_minimal.Api
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

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
