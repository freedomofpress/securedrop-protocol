module Libcrux_chacha20poly1305
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// The length of ChaCha20-Poly1305 keys.
let v_KEY_LEN: usize = mk_usize 32

/// The length of Poly1305 MAC tags.
let v_TAG_LEN: usize = mk_usize 16

/// The length of ChaCha20-Poly1305 nonces.
let v_NONCE_LEN: usize = mk_usize 12

/// Describes the error conditions of the  ChaCha20-Poly1305 AEAD.
type t_AeadError =
  | AeadError_PlaintextTooLarge : t_AeadError
  | AeadError_CiphertextTooLarge : t_AeadError
  | AeadError_AadTooLarge : t_AeadError
  | AeadError_CiphertextTooShort : t_AeadError
  | AeadError_PlaintextTooShort : t_AeadError
  | AeadError_InvalidCiphertext : t_AeadError

val t_AeadError_cast_to_repr (x: t_AeadError)
    : Prims.Pure isize Prims.l_True (fun _ -> Prims.l_True)
