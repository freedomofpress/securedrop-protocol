module Securedrop_protocol_minimal.Primitives.Provider.Blake2
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Domain-separated KDF: `Blake2b(domain || input)` truncated to 32 bytes
assume
val derive32': domain: t_Slice u8 -> input: t_Slice u8 -> t_Array u8 (mk_usize 32)

unfold
let derive32 = derive32'

/// Domain-separated KDF: `Blake2b(domain || input)` truncated to 64 bytes
assume
val derive64': domain: t_Slice u8 -> input: t_Slice u8 -> t_Array u8 (mk_usize 64)

unfold
let derive64 = derive64'
