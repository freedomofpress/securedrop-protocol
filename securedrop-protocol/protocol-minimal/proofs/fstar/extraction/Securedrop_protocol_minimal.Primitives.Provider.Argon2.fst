module Securedrop_protocol_minimal.Primitives.Provider.Argon2
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Derive a 64-byte master key from `passphrase` and `salt` via Argon2id
/// using OWASP-recommended params
assume
val derive_master_key': passphrase: t_Slice u8 -> salt: t_Slice u8 -> t_Array u8 (mk_usize 64)

unfold
let derive_master_key = derive_master_key'
