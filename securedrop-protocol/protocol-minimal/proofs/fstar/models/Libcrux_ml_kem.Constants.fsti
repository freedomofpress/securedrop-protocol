module Libcrux_ml_kem.Constants
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Coefficients per ring element
let v_COEFFICIENTS_IN_RING_ELEMENT: usize = mk_usize 256

/// Bits required per (uncompressed) ring element
let v_BITS_PER_RING_ELEMENT: usize = v_COEFFICIENTS_IN_RING_ELEMENT *! mk_usize 12

/// Bytes required per (uncompressed) ring element
let v_BYTES_PER_RING_ELEMENT: usize = v_BITS_PER_RING_ELEMENT /! mk_usize 8

/// The size of an ML-KEM shared secret.
let v_SHARED_SECRET_SIZE: usize = mk_usize 32

let v_CPA_PKE_KEY_GENERATION_SEED_SIZE: usize = mk_usize 32

/// SHA3 256 digest size
let v_H_DIGEST_SIZE: usize = mk_usize 32

/// K * BITS_PER_RING_ELEMENT / 8
/// [eurydice] Note that we can\'t use const generics here because that breaks
///            C extraction with eurydice.
val ranked_bytes_per_ring_element (rank: usize)
    : Prims.Pure usize
      (requires rank <=. mk_usize 4)
      (ensures
        fun result ->
          let result:usize = result in
          result =. ((rank *! v_BITS_PER_RING_ELEMENT <: usize) /! mk_usize 8 <: usize))
