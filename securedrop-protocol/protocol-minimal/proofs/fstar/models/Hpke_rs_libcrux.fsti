module Hpke_rs_libcrux
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Phantom type tag selecting the libcrux-backed HPKE crypto provider,
/// parameterised by its PRNG.
assume
type t_HpkeLibcrux (v_R: Type0) : Type0

/// The default PRNG of the libcrux-backed HPKE crypto provider.
assume
type t_HpkeLibcruxPrng : Type0
