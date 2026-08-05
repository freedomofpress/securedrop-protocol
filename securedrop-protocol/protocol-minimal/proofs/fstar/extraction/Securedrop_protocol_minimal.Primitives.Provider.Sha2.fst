module Securedrop_protocol_minimal.Primitives.Provider.Sha2
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// The length of a SHA-512 digest.
assume
val v_SHA512_LEN': usize

unfold
let v_SHA512_LEN = v_SHA512_LEN'

/// SHA-512 over `payload`.
assume
val sha512': payload: t_Slice u8 -> t_Array u8 (mk_usize 64)

unfold
let sha512 = sha512'
