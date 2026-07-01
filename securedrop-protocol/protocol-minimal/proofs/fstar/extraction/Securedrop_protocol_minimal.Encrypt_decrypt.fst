module Securedrop_protocol_minimal.Encrypt_decrypt
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  let open Securedrop_protocol_minimal.Primitives.X25519 in
  let open Securedrop_protocol_minimal.Traits in
  ()

let v_NR_ID: t_Slice u8 =
  (let list =
      [
        mk_u8 77; mk_u8 79; mk_u8 67; mk_u8 75; mk_u8 95; mk_u8 78; mk_u8 69; mk_u8 87; mk_u8 83;
        mk_u8 82; mk_u8 79; mk_u8 79; mk_u8 77; mk_u8 95; mk_u8 73; mk_u8 68
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 16);
    Rust_primitives.Hax.array_of_list 16 list)
  <:
  t_Slice u8

#push-options "--admit_smt_queries true"

/// Encrypt a message from a sender to a recipient (step 6).
/// Produces an [`Envelope`] containing:
/// - `ct^APKE`: SD-APKE ciphertext (encrypted message)
/// - `ct^PKE`: SD-PKE ciphertext (encrypted sender APKE public key)
/// - `(X, Z)`: hint for privacy-preserving message fetching
let encrypt
      (#v_R #v_Sender #v_Recipient: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i2:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_Sender)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Securedrop_protocol_minimal.Traits.t_UserPublic v_Recipient)
      (rng: v_R)
      (sender: v_Sender)
      (plaintext: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
      (recipient: v_Recipient)
    : (v_R & Securedrop_protocol_minimal.Ciphertext.t_Envelope) =
  let sk_s:Securedrop_protocol_minimal.Message.t_MessagePrivateKey =
    Securedrop_protocol_minimal.Traits.f_message_auth_key #v_Sender
      #FStar.Tactics.Typeclasses.solve
      sender
  in
  let pk_r:Securedrop_protocol_minimal.Message.t_MessagePublicKey =
    Securedrop_protocol_minimal.Traits.f_message_enc_pk #v_Recipient
      #FStar.Tactics.Typeclasses.solve
      recipient
  in
  let pk_r_fetch:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__into_bytes (Securedrop_protocol_minimal.Traits.f_fetch_pk
          #v_Recipient
          #FStar.Tactics.Typeclasses.solve
          recipient
        <:
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Message.t_MessageCiphertext
      Anyhow.t_Error) =
    Securedrop_protocol_minimal.Message.auth_enc #v_R
      rng
      sk_s
      pk_r
      (Alloc.Vec.impl_1__as_slice (Securedrop_protocol_minimal.Ciphertext.impl_Plaintext__to_bytes plaintext

            <:
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        <:
        t_Slice u8)
      v_NR_ID
      (pk_r_fetch <: t_Slice u8)
  in
  let rng:v_R = tmp0 in
  let ct_apke:Securedrop_protocol_minimal.Message.t_MessageCiphertext =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Message.t_MessageCiphertext
      #Anyhow.t_Error
      out
      "SD-APKE AuthEnc failed"
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error) =
    Securedrop_protocol_minimal.Primitives.X25519.generate_dh_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (hint_esk: Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey),
  (hint_epk: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      out
      "DH Keygen (hint) failed"
  in
  let (hint_sharedsecret: Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret):Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret
  =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Primitives.X25519.dh_shared_secret (Securedrop_protocol_minimal.Traits.f_fetch_pk
              #v_Recipient
              #FStar.Tactics.Typeclasses.solve
              recipient
            <:
            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
          (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPrivateKey__into_bytes hint_esk
            <:
            t_Array u8 (mk_usize 32))
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret
          Anyhow.t_Error)
      "Failed to generate shared secret"
  in
  let ct_pke:Securedrop_protocol_minimal.Metadata.t_MetadataCiphertext =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Metadata.t_MetadataCiphertext
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Metadata.encrypt (Securedrop_protocol_minimal.Traits.f_message_metadata_pk
              #v_Recipient
              #FStar.Tactics.Typeclasses.solve
              recipient
            <:
            Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey)
          (Securedrop_protocol_minimal.Traits.f_own_message_auth_pk #v_Sender
              #FStar.Tactics.Typeclasses.solve
              sender
            <:
            Securedrop_protocol_minimal.Message.t_MessagePublicKey)
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Metadata.t_MetadataCiphertext
          Anyhow.t_Error)
      "Valid Keybundle should allow metadata seal"
  in
  let hax_temp_output:Securedrop_protocol_minimal.Ciphertext.t_Envelope =
    {
      Securedrop_protocol_minimal.Ciphertext.f_ct_apke = ct_apke;
      Securedrop_protocol_minimal.Ciphertext.f_ct_pke = ct_pke;
      Securedrop_protocol_minimal.Ciphertext.f_mgdh_pubkey
      =
      Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__into_bytes hint_epk;
      Securedrop_protocol_minimal.Ciphertext.f_mgdh
      =
      Securedrop_protocol_minimal.Primitives.X25519.impl_DHSharedSecret__into_bytes hint_sharedsecret

    }
    <:
    Securedrop_protocol_minimal.Ciphertext.t_Envelope
  in
  rng, hax_temp_output <: (v_R & Securedrop_protocol_minimal.Ciphertext.t_Envelope)

#pop-options

#push-options "--admit_smt_queries true"

let decrypt
      (#v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_U)
      (receiver: v_U)
      (envelope: Securedrop_protocol_minimal.Ciphertext.t_Envelope)
    : Securedrop_protocol_minimal.Ciphertext.t_Plaintext =
  let
  (found:
    Core_models.Option.t_Option
    (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)):Core_models.Option.t_Option
  (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option
    (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  let found:Core_models.Option.t_Option
  (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            Securedrop_protocol_minimal.Keys.t_MessageKeyBundle)
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Keys.t_MessageKeyBundle
              (Alloc.Vec.impl_1__as_slice (Securedrop_protocol_minimal.Traits.f_keybundles #v_U
                      #FStar.Tactics.Typeclasses.solve
                      receiver
                    <:
                    Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.t_MessageKeyBundle
                      Alloc.Alloc.t_Global)
                <:
                t_Slice Securedrop_protocol_minimal.Keys.t_MessageKeyBundle)
            <:
            Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_MessageKeyBundle)
        <:
        Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.t_MessageKeyBundle)
      found
      (fun found bundle ->
          let found:Core_models.Option.t_Option
          (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle &
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
            found
          in
          let bundle:Securedrop_protocol_minimal.Keys.t_MessageKeyBundle = bundle in
          match
            Securedrop_protocol_minimal.Metadata.decrypt (Securedrop_protocol_minimal.Metadata.impl_MetadataKeyPair__private_key
                  bundle.Securedrop_protocol_minimal.Keys.f_metadata_kp
                <:
                Securedrop_protocol_minimal.Metadata.t_MetadataPrivateKey)
              envelope.Securedrop_protocol_minimal.Ciphertext.f_ct_pke
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok m ->
            let found:Core_models.Option.t_Option
            (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle &
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
              Core_models.Option.Option_Some
              (bundle, m
                <:
                (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle &
                  Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              <:
              Core_models.Option.t_Option
              (Securedrop_protocol_minimal.Keys.t_MessageKeyBundle &
                Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            in
            found
          | _ -> found)
  in
  let
  (bundle: Securedrop_protocol_minimal.Keys.t_MessageKeyBundle),
  (raw_metadata: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Option.impl__expect #(Securedrop_protocol_minimal.Keys.t_MessageKeyBundle &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      found
      "we should find exactly 1 result"
  in
  let sender_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey =
    Core_models.Result.impl__expect #Securedrop_protocol_minimal.Message.t_MessagePublicKey
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Message.impl_MessagePublicKey__from_bytes (Alloc.Vec.impl_1__as_slice
              raw_metadata
            <:
            t_Slice u8)
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Message.t_MessagePublicKey
          Anyhow.t_Error)
      "Metadata must contain valid sender APKE key tuple"
  in
  let pk_r_fetch:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__into_bytes (Securedrop_protocol_minimal.Traits.f_fetch_keypair
          #v_U
          #FStar.Tactics.Typeclasses.solve
          receiver
        <:
        (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
          Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey))
        ._2
  in
  let pt:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Core_models.Result.impl__expect #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Message.auth_dec (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__private_key
              bundle.Securedrop_protocol_minimal.Keys.f_apke
            <:
            Securedrop_protocol_minimal.Message.t_MessagePrivateKey)
          sender_pk
          envelope.Securedrop_protocol_minimal.Ciphertext.f_ct_apke
          v_NR_ID
          (pk_r_fetch <: t_Slice u8)
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
      "SD-APKE AuthDec failed"
  in
  Core_models.Result.impl__unwrap #Securedrop_protocol_minimal.Ciphertext.t_Plaintext
    #Anyhow.t_Error
    (Securedrop_protocol_minimal.Ciphertext.impl_Plaintext__from_bytes (Alloc.Vec.impl_1__as_slice pt

          <:
          t_Slice u8)
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext Anyhow.t_Error)

#pop-options

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
  let (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
    Securedrop_protocol_minimal.Primitives.X25519.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let eph_sk:t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32)) #Anyhow.t_Error out "Want dh scalar"
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
            let
            (tmp0: v_R),
            (out:
              Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
            =
              Securedrop_protocol_minimal.Primitives.encrypt_message_id #v_R
                (Securedrop_protocol_minimal.Primitives.X25519.impl_DHSharedSecret__into_bytes shared_secret

                  <:
                  t_Slice u8)
                (message_id <: t_Slice u8)
                rng
            in
            let rng:v_R = tmp0 in
            let enc_mid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
              Core_models.Result.impl__unwrap #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Anyhow.t_Error
                out
            in
            let kmid:t_Array u8 (mk_usize 44) =
              Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 44)
            in
            let kmid:t_Array u8 (mk_usize 44) =
              Core_models.Slice.impl__copy_from_slice #u8
                kmid
                (Alloc.Vec.impl_1__as_slice enc_mid <: t_Slice u8)
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

#pop-options

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
          let maybe_kmid_secret:Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret =
            Core_models.Result.impl__expect #Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret
              #Anyhow.t_Error
              (Securedrop_protocol_minimal.Primitives.X25519.dh_shared_secret (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__from_bytes
                      chall.Securedrop_protocol_minimal.Ciphertext.f_pmgdh
                    <:
                    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
                  (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPrivateKey__into_bytes (Core_models.Clone.f_clone
                          #Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey
                          #FStar.Tactics.Typeclasses.solve
                          (Securedrop_protocol_minimal.Traits.f_fetch_keypair #v_S
                              #FStar.Tactics.Typeclasses.solve
                              recipient
                            <:
                            (Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey &
                              Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey))
                            ._1
                        <:
                        Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey)
                    <:
                    t_Array u8 (mk_usize 32))
                <:
                Core_models.Result.t_Result
                  Securedrop_protocol_minimal.Primitives.X25519.t_DHSharedSecret Anyhow.t_Error)
              "Need 3-party DH (scalarmult) on pmgdh"
          in
          match
            Securedrop_protocol_minimal.Primitives.decrypt_message_id (Securedrop_protocol_minimal.Primitives.X25519.impl_DHSharedSecret__into_bytes
                  maybe_kmid_secret
                <:
                t_Slice u8)
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

#push-options "--admit_smt_queries true"

/// Build plaintext message, including pubkeys (for replies).
/// TODO: only sources need to attach their pubkeys (for replies),
/// but for toy purposes, everyone builds a Plaintext message the same way
let build_message
      (#iimpl_822573411_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Traits.t_UserPublic iimpl_822573411_)
      (sender: iimpl_822573411_)
      (message: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Securedrop_protocol_minimal.Ciphertext.t_Plaintext =
  let fetch_pk:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let fetch_pk:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      fetch_pk
      (Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__into_bytes (Core_models.Clone.f_clone
              #Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey
              #FStar.Tactics.Typeclasses.solve
              (Securedrop_protocol_minimal.Traits.f_fetch_pk #iimpl_822573411_
                  #FStar.Tactics.Typeclasses.solve
                  sender
                <:
                Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
            <:
            Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
        <:
        t_Slice u8)
  in
  let reply_key_pq_hybrid:t_Array u8 (mk_usize 1216) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1216)
  in
  let reply_key_pq_hybrid:t_Array u8 (mk_usize 1216) =
    Core_models.Slice.impl__copy_from_slice #u8
      reply_key_pq_hybrid
      (Securedrop_protocol_minimal.Metadata.impl_MetadataPublicKey__as_bytes (Securedrop_protocol_minimal.Traits.f_message_metadata_pk
              #iimpl_822573411_
              #FStar.Tactics.Typeclasses.solve
              sender
            <:
            Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey)
        <:
        t_Slice u8)
  in
  {
    Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key = fetch_pk;
    Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid = reply_key_pq_hybrid;
    Securedrop_protocol_minimal.Ciphertext.f_msg = message
  }
  <:
  Securedrop_protocol_minimal.Ciphertext.t_Plaintext

#pop-options
