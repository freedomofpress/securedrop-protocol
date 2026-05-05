module Hpke_rs_libcrux
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Phantom type tag selecting the libcrux-backed HPKE crypto provider.
assume
type t_HpkeLibcrux : Type0
