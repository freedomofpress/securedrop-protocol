module Securedrop_protocol_minimal.Encrypt_decrypt
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Ahash in
  let open Ahash.Fallback_hash in
  let open Allocator_api2.Stable.Alloc in
  let open Allocator_api2.Stable.Alloc.Global in
  let open Anyhow.Error in
  let open Hashbrown in
  let open Hashbrown.Map in
  let open Rand_core in
  let open Uuid in
  ()

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
let compute_fetch_challenges
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (store:
          Hashbrown.Map.t_HashMap Uuid.t_Uuid
            Securedrop_protocol_minimal.Ciphertext.t_Envelope
            (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
            Allocator_api2.Stable.Alloc.Global.t_Global)
      (total_responses: usize)
    : (v_R &
      Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
      total_responses
  in
  let (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
    Securedrop_protocol_minimal.Primitives.X25519.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let eph_sk:t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32)) #Anyhow.t_Error out "Want dh scalar"
  in
  let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global =
    Rust_primitives.Hax.Folds.fold_cf (Core_models.Iter.Traits.Collect.f_into_iter #(Hashbrown.Map.t_Keys
              Uuid.t_Uuid Securedrop_protocol_minimal.Ciphertext.t_Envelope)
          #FStar.Tactics.Typeclasses.solve
          (Hashbrown.Map.impl_4__keys #Uuid.t_Uuid
              #Securedrop_protocol_minimal.Ciphertext.t_Envelope
              #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
              #Allocator_api2.Stable.Alloc.Global.t_Global
              store
            <:
            Hashbrown.Map.t_Keys Uuid.t_Uuid Securedrop_protocol_minimal.Ciphertext.t_Envelope)
        <:
        Hashbrown.Map.t_Keys Uuid.t_Uuid Securedrop_protocol_minimal.Ciphertext.t_Envelope)
      responses
      (fun responses entry ->
          let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
            Alloc.Alloc.t_Global =
            responses
          in
          let entry:Uuid.t_Uuid = entry in
          let message_id:t_Array u8 (mk_usize 16) = Uuid.impl_Uuid__as_bytes entry in
          let envelope:Securedrop_protocol_minimal.Ciphertext.t_Envelope =
            Core_models.Option.impl__expect #Securedrop_protocol_minimal.Ciphertext.t_Envelope
              (Hashbrown.Map.impl_5__get #Uuid.t_Uuid
                  #Securedrop_protocol_minimal.Ciphertext.t_Envelope
                  #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
                  #Allocator_api2.Stable.Alloc.Global.t_Global
                  #Uuid.t_Uuid
                  store
                  entry
                <:
                Core_models.Option.t_Option Securedrop_protocol_minimal.Ciphertext.t_Envelope)
              "missing message for this uuid"
          in
          let shared_secret:Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret =
            Core_models.Result.impl__expect #Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret
              #Anyhow.t_Error
              (Securedrop_protocol_minimal.Primitives.X25519.dh_shared_secret (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__from_bytes
                      envelope.Securedrop_protocol_minimal.Ciphertext.f_mgdh
                    <:
                    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
                  eph_sk
                <:
                Core_models.Result.t_Result
                  Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret Anyhow.t_Error)
              "Need 3-party dh shared secret"
          in
          let enc_mid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Core_models.Result.impl__unwrap #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #Anyhow.t_Error
              (Securedrop_protocol_minimal.Primitives.encrypt_message_id (Securedrop_protocol_minimal.Primitives.X25519.impl_DHSharedSecret__into_bytes
                      shared_secret
                    <:
                    t_Slice u8)
                  (message_id <: t_Slice u8)
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
              )
          in
          let args:usize = Securedrop_protocol_minimal.Constants.v_LEN_KMID <: usize in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          let kmid:t_Array u8 (mk_usize 44) =
            Core_models.Result.impl__expect #(t_Array u8 (mk_usize 44))
              #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #(t_Array u8 (mk_usize 44))
                  #FStar.Tactics.Typeclasses.solve
                  enc_mid
                <:
                Core_models.Result.t_Result (t_Array u8 (mk_usize 44))
                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  (Core_models.Hint.must_use #Alloc.String.t_String
                      (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                              (mk_usize 1)
                              (let list = ["Need "; " bytes"] in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                                Rust_primitives.Hax.array_of_list 2 list)
                              args
                            <:
                            Core_models.Fmt.t_Arguments)
                        <:
                        Alloc.String.t_String)
                    <:
                    Alloc.String.t_String)
                <:
                string)
          in
          let pmgdh:Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret =
            Core_models.Result.impl__expect #Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret
              #Anyhow.t_Error
              (Securedrop_protocol_minimal.Primitives.X25519.dh_shared_secret (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__from_bytes
                      envelope.Securedrop_protocol_minimal.Ciphertext.f_mgdh_pubkey
                    <:
                    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
                  eph_sk
                <:
                Core_models.Result.t_Result
                  Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret Anyhow.t_Error)
              "Need pmgdh"
          in
          let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
            Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
              ({
                  Securedrop_protocol_minimal.Ciphertext.f_enc_id = kmid;
                  Securedrop_protocol_minimal.Ciphertext.f_pmgdh
                  =
                  Securedrop_protocol_minimal.Primitives.X25519.impl_DHSharedSecret__into_bytes pmgdh

                  <:
                  t_Array u8 (mk_usize 32)
                }
                <:
                Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
          in
          if
            (Alloc.Vec.impl_1__len #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                #Alloc.Alloc.t_Global
                responses
              <:
              usize) =.
            total_responses
          then
            Core_models.Ops.Control_flow.ControlFlow_Break
            ((), responses
              <:
              (Prims.unit &
                Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                  Alloc.Alloc.t_Global))
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Prims.unit &
                Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                  Alloc.Alloc.t_Global)
              (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                  Alloc.Alloc.t_Global)
          else
            Core_models.Ops.Control_flow.ControlFlow_Continue responses
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Prims.unit &
                Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                  Alloc.Alloc.t_Global)
              (Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
                  Alloc.Alloc.t_Global))
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
          let (pad_kmid: t_Array u8 (mk_usize 44)):t_Array u8 (mk_usize 44) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 44)
          in
          let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 44)) =
            Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng pad_kmid
          in
          let rng:v_R = tmp0 in
          let pad_kmid:t_Array u8 (mk_usize 44) = tmp1 in
          let _:Prims.unit = () in
          let (pad_pmgdh: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
          in
          let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
            Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng pad_pmgdh
          in
          let rng:v_R = tmp0 in
          let pad_pmgdh:t_Array u8 (mk_usize 32) = tmp1 in
          let _:Prims.unit = () in
          let responses:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
            Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
              ({
                  Securedrop_protocol_minimal.Ciphertext.f_enc_id = pad_kmid;
                  Securedrop_protocol_minimal.Ciphertext.f_pmgdh = pad_pmgdh
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
