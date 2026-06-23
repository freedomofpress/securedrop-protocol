module Securedrop_protocol_minimal.Primitives.Provider.Rng
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  ()

/// Fill `dest` with random bytes from `rng`
assume
val fill_bytes':
    #v_R: Type0 ->
    v_N: usize ->
    {| i0: Rand_core.t_RngCore v_R |} ->
    {| i1: Rand_core.t_CryptoRng v_R |} ->
    rng: v_R ->
    dest: t_Array u8 v_N
  -> (v_R & t_Array u8 v_N)

unfold
let fill_bytes
      (#v_R: Type0)
      (v_N: usize)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
     = fill_bytes' #v_R v_N #i0 #i1
