module Securedrop_protocol_minimal.Primitives
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_chacha20poly1305 in
  ()

/// Fixed number of message ID entries to return in privacy-preserving fetch
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
let v_MESSAGE_ID_FETCH_SIZE: usize = mk_usize 10

/// Fixed, public salt for challenge id encryption.
let v_CHALLENGE_SALT: t_Slice u8 =
  (let list =
      [
        mk_u8 115; mk_u8 101; mk_u8 99; mk_u8 117; mk_u8 114; mk_u8 101; mk_u8 100; mk_u8 114;
        mk_u8 111; mk_u8 112; mk_u8 45; mk_u8 99; mk_u8 104; mk_u8 97; mk_u8 108; mk_u8 108;
        mk_u8 101; mk_u8 110; mk_u8 103; mk_u8 101; mk_u8 45; mk_u8 118; mk_u8 49
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 23);
    Rust_primitives.Hax.array_of_list 23 list)
  <:
  t_Slice u8

/// Derive symmetric key used for ChaCha20-Poly1305 challenge encryption
/// This is used in step 7 for encrypting message IDs with a shared secret
assume
val derive_challenge_key':
    shared_secret: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey ->
    newsroom_id: t_Slice u8
  -> t_Array u8 (mk_usize 32)

unfold
let derive_challenge_key = derive_challenge_key'

/// Symmetric encryption for message IDs using ChaCha20-Poly1305
/// This is used in step 7 for encrypting message IDs with a shared secret
let encrypt_message_id (key: t_Array u8 (mk_usize 32)) (message_id: t_Slice u8)
    : Prims.Pure
      (Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
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
  let nonce:t_Array u8 (mk_usize 12) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 12) in
  let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #u8
      (mk_u8 0)
      ((Core_models.Slice.impl__len #u8 message_id <: usize) +!
        Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
        <:
        usize)
  in
  let
  (tmp0: t_Slice u8),
  (out: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError) =
    Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.encrypt key
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
  match out <: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError with
  | Core_models.Result.Result_Ok _ ->
    let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8
        #Alloc.Alloc.t_Global
        output
        (Alloc.Vec.impl_1__as_slice ciphertext <: t_Slice u8)
    in
    Core_models.Result.Result_Ok output
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
  | Core_models.Result.Result_Err e ->
    let args:Libcrux_chacha20poly1305.t_AeadError = e <: Libcrux_chacha20poly1305.t_AeadError in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
      let list = [Core_models.Fmt.Rt.impl__new_debug #Libcrux_chacha20poly1305.t_AeadError args] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
      Rust_primitives.Hax.array_of_list 1 list
    in
    Core_models.Result.Result_Err
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
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error

/// Symmetric decryption for message IDs using ChaCha20-Poly1305
/// This is used in step 7 for decrypting message IDs with a shared secret
let decrypt_message_id (key: t_Array u8 (mk_usize 32)) (encrypted_data: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  if
    (Core_models.Slice.impl__len #u8 encrypted_data <: usize) <.
    Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
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
    let nonce:t_Array u8 (mk_usize 12) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 12) in
    let plaintext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #u8
        (mk_u8 0)
        ((Core_models.Slice.impl__len #u8 encrypted_data <: usize) -!
          Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.v_TAG_LEN
          <:
          usize)
    in
    let
    (tmp0: t_Slice u8),
    (out: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError) =
      Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305.decrypt key
        (Alloc.Vec.impl_1__as_slice plaintext <: t_Slice u8)
        encrypted_data
        ((let list:Prims.list u8 = [] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
            Rust_primitives.Hax.array_of_list 0 list)
          <:
          t_Slice u8)
        nonce
    in
    let plaintext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Slice.impl__to_vec tmp0 in
    match
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
                [Core_models.Fmt.Rt.impl__new_debug #Libcrux_chacha20poly1305.t_AeadError args]
              in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list
            in
            Anyhow.Error.impl__msg #Alloc.String.t_String
              (Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["ChaCha20-Poly1305 decryption failed: "] in
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
