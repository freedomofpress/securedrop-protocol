module Libcrux_ecdh.P256_internal
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_PrivateKey = | PrivateKey : t_Array u8 (mk_usize 32) -> t_PrivateKey

type t_PublicKey = | PublicKey : t_Array u8 (mk_usize 64) -> t_PublicKey

/// Output of a scalar multiplication between a public key and a secret key.
/// This value is NOT (!) safe for use as a key and needs to be processed in a round of key
/// derivation, to ensure both that the output is uniformly random and that unkown key share
/// attacks can not happen.
type t_SharedSecret = | SharedSecret : t_Array u8 (mk_usize 64) -> t_SharedSecret
