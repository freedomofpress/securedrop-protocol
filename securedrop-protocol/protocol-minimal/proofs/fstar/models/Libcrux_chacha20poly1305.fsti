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
