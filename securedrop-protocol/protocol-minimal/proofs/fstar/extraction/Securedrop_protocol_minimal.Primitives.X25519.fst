module Securedrop_protocol_minimal.Primitives.X25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// An X25519 public key.
type t_DHPublicKey = | DHPublicKey : t_Array u8 (mk_usize 32) -> t_DHPublicKey

/// An X25519 private key.
type t_DHPrivateKey = | DHPrivateKey : t_Array u8 (mk_usize 32) -> t_DHPrivateKey

let typed (sk pk: t_Array u8 (mk_usize 32))
    : Prims.Pure (Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error =
            result
          in
          Core_models.Result.impl__is_ok #(t_DHPrivateKey & t_DHPublicKey) #Anyhow.t_Error result) =
  Core_models.Result.Result_Ok
  ((DHPrivateKey sk <: t_DHPrivateKey), (DHPublicKey pk <: t_DHPublicKey)
    <:
    (t_DHPrivateKey & t_DHPublicKey))
  <:
  Core_models.Result.t_Result (t_DHPrivateKey & t_DHPublicKey) Anyhow.t_Error
