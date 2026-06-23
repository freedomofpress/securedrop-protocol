module Securedrop_protocol_minimal.Primitives.Provider.Uuid_parse
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Parse a `Uuid` from bytes
assume
val from_slice': bytes: t_Slice u8 -> Uuid.t_Uuid

unfold
let from_slice = from_slice'
