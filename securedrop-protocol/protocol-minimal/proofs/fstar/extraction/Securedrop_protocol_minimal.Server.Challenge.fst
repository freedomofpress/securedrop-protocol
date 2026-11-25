module Securedrop_protocol_minimal.Server.Challenge
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  ()

assume
val sort_by_id': entries: t_Slice Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
  -> t_Slice Securedrop_protocol_minimal.Wire.Core.t_FetchResponse

unfold
let sort_by_id = sort_by_id'

let make_response
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (message_id: t_Array u8 (mk_usize 16))
      (mgdh mgdh_pubkey: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)
      (nr_id: t_Slice u8)
    : Prims.Pure (v_R & Securedrop_protocol_minimal.Wire.Core.t_FetchResponse)
      (requires
        (Core_models.Slice.impl__len #u8 nr_id <: usize) <=.
        (cast (Core_models.Num.impl_u32__MAX <: u32) <: usize))
      (fun _ -> Prims.l_True) =
  let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let eph_sk:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey = out in
  let shared_secret:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
    Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret mgdh eph_sk
  in
  let key:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Schemes.Challenge.derive_challenge_key shared_secret nr_id
  in
  let enc_mid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Securedrop_protocol_minimal.Schemes.Challenge.encrypt_message_id key message_id
  in
  let kmid:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let kmid:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      kmid
      (Alloc.Vec.impl_1__as_slice enc_mid <: t_Slice u8)
  in
  let pmgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
    Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret mgdh_pubkey eph_sk
  in
  let hax_temp_output:Securedrop_protocol_minimal.Wire.Core.t_FetchResponse =
    {
      Securedrop_protocol_minimal.Wire.Core.f_enc_id = kmid;
      Securedrop_protocol_minimal.Wire.Core.f_pmgdh = pmgdh
    }
    <:
    Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
  in
  rng, hax_temp_output <: (v_R & Securedrop_protocol_minimal.Wire.Core.t_FetchResponse)

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as an encrypted message id and a DH agreement output.
/// Slots without a real entry are filled with decoy challenges, computed the same way
/// as real ones but over randomly sampled DH public keys and an all-zero message id.
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
/// # Security
/// The number of real entries is secret, i.e. the timing must
/// not leak the number of ciphertexts on the server. This function does the
/// same work for each of the slots whether it has a real entry or a decoy.
let compute_fetch_challenges
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (entries:
          t_Slice (t_Array u8 (mk_usize 16) & Securedrop_protocol_minimal.Wire.Core.t_Envelope))
      (total_responses: usize)
    : (v_R &
      Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
      total_responses
  in
  let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.random_dh_public_key #v_R rng
  in
  let rng:v_R = tmp0 in
  let decoy_mgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey = out in
  let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.random_dh_public_key #v_R rng
  in
  let rng:v_R = tmp0 in
  let decoy_mgdh_pubkey:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey = out in
  let
  (responses:
    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse Alloc.Alloc.t_Global),
  (rng: v_R) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      total_responses
      (fun temp_0_ i ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let i:usize = i in
          (Alloc.Vec.impl_1__len #Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
            <:
            usize) =.
          i
          <:
          bool)
      (responses, rng
        <:
        (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse Alloc.Alloc.t_Global &
          v_R))
      (fun temp_0_ i ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let i:usize = i in
          let (rng: v_R), (response: Securedrop_protocol_minimal.Wire.Core.t_FetchResponse) =
            if
              i <.
              (Core_models.Slice.impl__len #(t_Array u8 (mk_usize 16) &
                    Securedrop_protocol_minimal.Wire.Core.t_Envelope)
                  entries
                <:
                usize)
            then
              let entry:(t_Array u8 (mk_usize 16) & Securedrop_protocol_minimal.Wire.Core.t_Envelope
              ) =
                entries.[ i ]
              in
              let (tmp0: v_R), (out: Securedrop_protocol_minimal.Wire.Core.t_FetchResponse) =
                make_response #v_R
                  rng
                  entry._1
                  entry._2.Securedrop_protocol_minimal.Wire.Core.f_mgdh
                  entry._2.Securedrop_protocol_minimal.Wire.Core.f_mgdh_pubkey
                  (Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID <: t_Slice u8)
              in
              let rng:v_R = tmp0 in
              rng, out <: (v_R & Securedrop_protocol_minimal.Wire.Core.t_FetchResponse)
            else
              let (tmp0: v_R), (out: Securedrop_protocol_minimal.Wire.Core.t_FetchResponse) =
                make_response #v_R
                  rng
                  (Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 16) <: t_Array u8 (mk_usize 16))
                  decoy_mgdh
                  decoy_mgdh_pubkey
                  (Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID <: t_Slice u8)
              in
              let rng:v_R = tmp0 in
              rng, out <: (v_R & Securedrop_protocol_minimal.Wire.Core.t_FetchResponse)
          in
          let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
            Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
              response
          in
          responses, rng
          <:
          (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
              Alloc.Alloc.t_Global &
            v_R))
  in
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
    Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (sort_by_id (Alloc.Vec.impl_1__as_slice responses
            <:
            t_Slice Securedrop_protocol_minimal.Wire.Core.t_FetchResponse)
        <:
        t_Slice Securedrop_protocol_minimal.Wire.Core.t_FetchResponse)
  in
  let hax_temp_output:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse
    Alloc.Alloc.t_Global =
    responses
  in
  rng, hax_temp_output
  <:
  (v_R & Alloc.Vec.t_Vec Securedrop_protocol_minimal.Wire.Core.t_FetchResponse Alloc.Alloc.t_Global)
