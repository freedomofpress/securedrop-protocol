module Securedrop_protocol_minimal.Server.Challenge
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  ()

#push-options "--admit_smt_queries true"

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
/// Note this is marked lax temporaily due to the `.expect()`/`push` panic freedom requirement
let compute_fetch_challenges
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (entries:
          t_Slice (t_Array u8 (mk_usize 16) & Securedrop_protocol_minimal.Ciphertext.t_Envelope))
      (total_responses: usize)
    : (v_R &
      Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
      total_responses
  in
  let
  (responses:
    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global),
  (rng: v_R) =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            (t_Array u8 (mk_usize 16) & Securedrop_protocol_minimal.Ciphertext.t_Envelope))
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #(t_Array u8 (mk_usize 16) &
                Securedrop_protocol_minimal.Ciphertext.t_Envelope)
              entries
            <:
            Core_models.Slice.Iter.t_Iter
            (t_Array u8 (mk_usize 16) & Securedrop_protocol_minimal.Ciphertext.t_Envelope))
        <:
        Core_models.Slice.Iter.t_Iter
        (t_Array u8 (mk_usize 16) & Securedrop_protocol_minimal.Ciphertext.t_Envelope))
      (responses, rng
        <:
        (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global &
          v_R))
      (fun temp_0_ temp_1_ ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let
          (message_id: t_Array u8 (mk_usize 16)),
          (envelope: Securedrop_protocol_minimal.Ciphertext.t_Envelope) =
            temp_1_
          in
          if
            (Alloc.Vec.impl_1__len #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                #Alloc.Alloc.t_Global
                responses
              <:
              usize) <.
            total_responses
            <:
            bool
          then
            let
            (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey) =
              Securedrop_protocol_minimal.Primitives.Ristretto255.generate_random_scalar #v_R rng
            in
            let rng:v_R = tmp0 in
            let eph_sk:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey = out in
            let shared_secret:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
              Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret envelope
                  .Securedrop_protocol_minimal.Ciphertext.f_mgdh
                eph_sk
            in
            let key:t_Array u8 (mk_usize 32) =
              Core_models.Result.impl__unwrap #(t_Array u8 (mk_usize 32))
                #Anyhow.t_Error
                (Securedrop_protocol_minimal.Schemes.Challenge.derive_challenge_key shared_secret
                    Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID
                  <:
                  Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
            in
            let enc_mid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
              Core_models.Result.impl__unwrap #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Anyhow.t_Error
                (Securedrop_protocol_minimal.Schemes.Challenge.encrypt_message_id key
                    (message_id <: t_Slice u8)
                  <:
                  Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    Anyhow.t_Error)
            in
            let kmid:t_Array u8 (mk_usize 32) =
              Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
            in
            let kmid:t_Array u8 (mk_usize 32) =
              Core_models.Slice.impl__copy_from_slice #u8
                kmid
                (Alloc.Vec.impl_1__as_slice enc_mid <: t_Slice u8)
            in
            let pmgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
              Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret envelope
                  .Securedrop_protocol_minimal.Ciphertext.f_mgdh_pubkey
                eph_sk
            in
            let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                #Alloc.Alloc.t_Global
                responses
                ({
                    Securedrop_protocol_minimal.Ciphertext.f_enc_id = kmid;
                    Securedrop_protocol_minimal.Ciphertext.f_pmgdh = pmgdh
                  }
                  <:
                  Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
            in
            responses, rng
            <:
            (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                Alloc.Alloc.t_Global &
              v_R)
          else
            responses, rng
            <:
            (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                Alloc.Alloc.t_Global &
              v_R))
  in
  let
  (responses:
    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global),
  (rng: v_R) =
    Rust_primitives.Hax.while_loop (fun temp_0_ ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          true)
      (fun temp_0_ ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          (Alloc.Vec.impl_1__len #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
            <:
            usize) <.
          total_responses
          <:
          bool)
      (fun temp_0_ ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
      (responses, rng
        <:
        (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global &
          v_R))
      (fun temp_0_ ->
          let
          (responses:
            Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global),
          (rng: v_R) =
            temp_0_
          in
          let (pad_kmid: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
          in
          let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
            Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng pad_kmid
          in
          let rng:v_R = tmp0 in
          let pad_kmid:t_Array u8 (mk_usize 32) = tmp1 in
          let _:Prims.unit = () in
          let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)
          =
            Securedrop_protocol_minimal.Primitives.Ristretto255.random_dh_public_key #v_R rng
          in
          let rng:v_R = tmp0 in
          let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
            Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
              ({
                  Securedrop_protocol_minimal.Ciphertext.f_enc_id = pad_kmid;
                  Securedrop_protocol_minimal.Ciphertext.f_pmgdh = out
                }
                <:
                Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
          in
          responses, rng
          <:
          (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              Alloc.Alloc.t_Global &
            v_R))
  in
  let hax_temp_output:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global =
    responses
  in
  rng, hax_temp_output
  <:
  (v_R & Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global
  )

#pop-options
