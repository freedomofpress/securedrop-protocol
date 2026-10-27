module Securedrop_protocol_minimal.Client.Challenge
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Securedrop_protocol_minimal.Traits in
  ()

#push-options "--admit_smt_queries true"

/// Solve fetch challenges (encrypted message IDs) and return array of valid message_ids.
/// TODO: For simplicity, serialize/deserialize is skipped
let solve_fetch_challenges
      (#v_S: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_S)
      (recipient: v_S)
      (challenges: t_Slice Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
    : Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global =
  let (message_ids: Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global):Alloc.Vec.t_Vec Uuid.t_Uuid
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #Uuid.t_Uuid ()
  in
  let message_ids:Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
              challenges
            <:
            Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
        <:
        Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Ciphertext.t_FetchResponse)
      message_ids
      (fun message_ids chall ->
          let message_ids:Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global = message_ids in
          let chall:Securedrop_protocol_minimal.Ciphertext.t_FetchResponse = chall in
          let maybe_kmid_secret:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
            Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret chall
                .Securedrop_protocol_minimal.Ciphertext.f_pmgdh
              (Securedrop_protocol_minimal.Traits.f_fetch_keypair #v_S
                  #FStar.Tactics.Typeclasses.solve
                  recipient
                <:
                (Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey &
                  Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey))
                ._1
          in
          let challenge_key:t_Array u8 (mk_usize 32) =
            Core_models.Result.impl__unwrap #(t_Array u8 (mk_usize 32))
              #Anyhow.t_Error
              (Securedrop_protocol_minimal.Schemes.Challenge.derive_challenge_key maybe_kmid_secret
                  Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID
                <:
                Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
          in
          match
            Securedrop_protocol_minimal.Schemes.Challenge.decrypt_message_id challenge_key
              (chall.Securedrop_protocol_minimal.Ciphertext.f_enc_id <: t_Slice u8)
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok message_id_bytes ->
            let uuid:Uuid.t_Uuid =
              Securedrop_protocol_minimal.Primitives.Provider.Uuid_parse.from_slice (Alloc.Vec.impl_1__as_slice
                    message_id_bytes
                  <:
                  t_Slice u8)
            in
            let message_ids:Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #Uuid.t_Uuid #Alloc.Alloc.t_Global message_ids uuid
            in
            message_ids
          | Core_models.Result.Result_Err _ -> message_ids)
  in
  message_ids

#pop-options
