module Libcrux_traits.Kem.Arrayref
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Opaque error returned by a KEM's `encaps` operation.
assume
type t_EncapsError : Type0

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_EncapsError_Debug: Core_models.Fmt.t_Debug t_EncapsError

/// Opaque error returned by a KEM's `decaps` operation.
assume
type t_DecapsError : Type0

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_DecapsError_Debug: Core_models.Fmt.t_Debug t_DecapsError
