// Minimal stub for `anyhow`: satisfies type-checking but provides no other
// proof guarantees, since anyhow is out of scope for verification.

module Anyhow

val t_Error:Type0

noeq
type t__private = {
  format_err:Core_models.Fmt.t_Arguments -> t_Error;
  must_use:t_Error -> t_Error
}

val __private:t__private