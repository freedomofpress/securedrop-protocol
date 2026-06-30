module Securedrop_protocol_minimal.Primitives
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_chacha20poly1305 in
  let open Rand_core in
  ()

/// Fixed number of message ID entries to return in privacy-preserving fetch
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
let v_MESSAGE_ID_FETCH_SIZE: usize = mk_usize 10

/// Symmetric encryption for message IDs using ChaCha20-Poly1305
/// This is used in step 7 for encrypting message IDs with a shared secret
let encrypt_message_id
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (key message_id: t_Slice u8)
      (rng: v_R)
    : Prims.Pure
      (v_R & Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
      (requires
        (Core_models.Slice.impl__len #u8 message_id <: usize) <=.
        ((Core_models.Num.impl_usize__MAX -!
            Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_NONCE_LEN
            <:
            usize) -!
          Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
          <:
          usize))
      (fun _ -> Prims.l_True) =
  if
    (Core_models.Slice.impl__len #u8 key <: usize) <>.
    Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_KEY_LEN
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["Invalid key length"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    rng,
    (Core_models.Result.Result_Err (Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
  else
    let nonce:t_Array u8 (mk_usize 12) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 12) in
    let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 12)) =
      Securedrop_protocol_minimal.Primitives.Provider.Rng.fill_bytes #v_R (mk_usize 12) rng nonce
    in
    let rng:v_R = tmp0 in
    let nonce:t_Array u8 (mk_usize 12) = tmp1 in
    let _:Prims.unit = () in
    let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
    let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global output (nonce <: t_Slice u8)
    in
    let ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #u8
        (mk_u8 0)
        ((Core_models.Slice.impl__len #u8 message_id <: usize) +!
          Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
          <:
          usize)
    in
    let result:Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
      Core_models.Array.t_TryFromSliceError =
      Core_models.Convert.f_try_into #(t_Slice u8)
        #(t_Array u8 (mk_usize 32))
        #FStar.Tactics.Typeclasses.solve
        key
    in
    match
      Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
        #Core_models.Array.t_TryFromSliceError
        #Anyhow.t_Error
        #(Core_models.Array.t_TryFromSliceError -> Anyhow.t_Error)
        result
        (fun temp_0_ ->
            let _:Core_models.Array.t_TryFromSliceError = temp_0_ in
            let error:Anyhow.t_Error =
              Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                    (let list = ["Key length mismatch"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core_models.Fmt.t_Arguments)
            in
            Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
    with
    | Core_models.Result.Result_Ok key_array ->
      let
      (tmp0: t_Slice u8),
      (out: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError) =
        Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.encrypt key_array
          message_id
          (Alloc.Vec.impl_1__as_slice ciphertext <: t_Slice u8)
          ((let list:Prims.list u8 = [] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
              Rust_primitives.Hax.array_of_list 0 list)
            <:
            t_Slice u8)
          nonce
      in
      let ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Slice.impl__to_vec tmp0 in
      (match out <: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError with
        | Core_models.Result.Result_Ok _ ->
          let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Alloc.Vec.impl_2__extend_from_slice #u8
              #Alloc.Alloc.t_Global
              output
              (Alloc.Vec.impl_1__as_slice ciphertext <: t_Slice u8)
          in
          let hax_temp_output:Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            Anyhow.t_Error =
            Core_models.Result.Result_Ok output
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
          in
          rng, hax_temp_output
          <:
          (v_R &
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
        | Core_models.Result.Result_Err e ->
          let args:Libcrux_chacha20poly1305.t_AeadError =
            e <: Libcrux_chacha20poly1305.t_AeadError
          in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list =
              [Core_models.Fmt.Rt.impl__new_debug #Libcrux_chacha20poly1305.t_AeadError args]
            in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          rng,
          (Core_models.Result.Result_Err
            (Anyhow.Error.impl__msg #Alloc.String.t_String
                (Core_models.Hint.must_use #Alloc.String.t_String
                    (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                            (mk_usize 1)
                            (let list = ["ChaCha20-Poly1305 encryption failed: "] in
                              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                              Rust_primitives.Hax.array_of_list 1 list)
                            args
                          <:
                          Core_models.Fmt.t_Arguments)
                      <:
                      Alloc.String.t_String)
                  <:
                  Alloc.String.t_String))
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
          <:
          (v_R &
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error))
    | Core_models.Result.Result_Err err ->
      rng,
      (Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
      <:
      (v_R & Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)

/// Symmetric decryption for message IDs using ChaCha20-Poly1305
/// This is used in step 7 for decrypting message IDs with a shared secret
let decrypt_message_id (key encrypted_data: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  if
    (Core_models.Slice.impl__len #u8 key <: usize) <>.
    Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_KEY_LEN
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["Invalid key length"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    Core_models.Result.Result_Err (Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
  else
    if
      (Core_models.Slice.impl__len #u8 encrypted_data <: usize) <.
      (Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_NONCE_LEN +!
        Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
        <:
        usize)
    then
      let error:Anyhow.t_Error =
        Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
              (let list = ["Encrypted data too short"] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
            <:
            Core_models.Fmt.t_Arguments)
      in
      Core_models.Result.Result_Err (Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
    else
      let nonce_r:Core_models.Result.t_Result (t_Array u8 (mk_usize 12))
        Core_models.Array.t_TryFromSliceError =
        Core_models.Convert.f_try_into #(t_Slice u8)
          #(t_Array u8 (mk_usize 12))
          #FStar.Tactics.Typeclasses.solve
          (encrypted_data.[ {
                Core_models.Ops.Range.f_end
                =
                Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_NONCE_LEN
              }
              <:
              Core_models.Ops.Range.t_RangeTo usize ]
            <:
            t_Slice u8)
      in
      match
        Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 12))
          #Core_models.Array.t_TryFromSliceError
          #Anyhow.t_Error
          #(Core_models.Array.t_TryFromSliceError -> Anyhow.t_Error)
          nonce_r
          (fun temp_0_ ->
              let _:Core_models.Array.t_TryFromSliceError = temp_0_ in
              let error:Anyhow.t_Error =
                Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                      (let list = ["Nonce extraction failed"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                    <:
                    Core_models.Fmt.t_Arguments)
              in
              Anyhow.__private.must_use error)
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 12)) Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok (nonce: t_Array u8 (mk_usize 12)) ->
        let ciphertext:t_Slice u8 =
          encrypted_data.[ {
              Core_models.Ops.Range.f_start
              =
              Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_NONCE_LEN
            }
            <:
            Core_models.Ops.Range.t_RangeFrom usize ]
        in
        let plaintext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.from_elem #u8
            (mk_u8 0)
            ((Core_models.Slice.impl__len #u8 ciphertext <: usize) -!
              Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
              <:
              usize)
        in
        let key_arr_res:Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
          Core_models.Array.t_TryFromSliceError =
          Core_models.Convert.f_try_into #(t_Slice u8)
            #(t_Array u8 (mk_usize 32))
            #FStar.Tactics.Typeclasses.solve
            key
        in
        (match
            Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
              #Core_models.Array.t_TryFromSliceError
              #Anyhow.t_Error
              #(Core_models.Array.t_TryFromSliceError -> Anyhow.t_Error)
              key_arr_res
              (fun temp_0_ ->
                  let _:Core_models.Array.t_TryFromSliceError = temp_0_ in
                  let error:Anyhow.t_Error =
                    Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                          (let list = ["Key length mismatch"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                        <:
                        Core_models.Fmt.t_Arguments)
                  in
                  Anyhow.__private.must_use error)
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok (key_array: t_Array u8 (mk_usize 32)) ->
            let
            (tmp0: t_Slice u8),
            (out: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError) =
              Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.decrypt key_array
                (Alloc.Vec.impl_1__as_slice plaintext <: t_Slice u8)
                ciphertext
                ((let list:Prims.list u8 = [] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
                    Rust_primitives.Hax.array_of_list 0 list)
                  <:
                  t_Slice u8)
                nonce
            in
            let plaintext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Slice.impl__to_vec tmp0 in
            (match
                Core_models.Result.impl__map_err #Prims.unit
                  #Libcrux_chacha20poly1305.t_AeadError
                  #Anyhow.t_Error
                  #(Libcrux_chacha20poly1305.t_AeadError -> Anyhow.t_Error)
                  out
                  (fun e ->
                      let e:Libcrux_chacha20poly1305.t_AeadError = e in
                      let args:Libcrux_chacha20poly1305.t_AeadError =
                        e <: Libcrux_chacha20poly1305.t_AeadError
                      in
                      let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                        let list =
                          [
                            Core_models.Fmt.Rt.impl__new_debug #Libcrux_chacha20poly1305.t_AeadError
                              args
                          ]
                        in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list
                      in
                      Anyhow.Error.impl__msg #Alloc.String.t_String
                        (Core_models.Hint.must_use #Alloc.String.t_String
                            (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                                    (mk_usize 1)
                                    (let list = ["ChaCha20-Poly1305 decryption failed: "] in
                                      FStar.Pervasives.assert_norm
                                      (Prims.eq2 (List.Tot.length list) 1);
                                      Rust_primitives.Hax.array_of_list 1 list)
                                    args
                                  <:
                                  Core_models.Fmt.t_Arguments)
                              <:
                              Alloc.String.t_String)
                          <:
                          Alloc.String.t_String))
                <:
                Core_models.Result.t_Result Prims.unit Anyhow.t_Error
              with
              | Core_models.Result.Result_Ok _ ->
                Core_models.Result.Result_Ok plaintext
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
              | Core_models.Result.Result_Err err ->
                Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
            )
          | Core_models.Result.Result_Err err ->
            Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
