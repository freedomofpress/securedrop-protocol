module Securedrop_protocol_minimal.Primitives.Provider
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_NoRng = | NoRng : t_NoRng

type t_NoRngError = | NoRngError : t_NoRngError

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl': Core_models.Fmt.t_Debug t_NoRngError

unfold
let impl = impl'
