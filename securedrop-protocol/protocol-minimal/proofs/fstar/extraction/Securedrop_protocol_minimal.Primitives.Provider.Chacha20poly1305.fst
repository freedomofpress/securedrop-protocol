module Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let v_KEY_LEN: usize = Libcrux_chacha20poly1305.v_KEY_LEN

let v_NONCE_LEN: usize = Libcrux_chacha20poly1305.v_NONCE_LEN

let v_TAG_LEN: usize = Libcrux_chacha20poly1305.v_TAG_LEN

assume
val encrypt':
    key: t_Array u8 (mk_usize 32) ->
    plaintext: t_Slice u8 ->
    ciphertext: t_Slice u8 ->
    aad: t_Slice u8 ->
    nonce: t_Array u8 (mk_usize 12)
  -> Prims.Pure
      (t_Slice u8 & Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError)
      Prims.l_True
      (ensures
        fun temp_0_ ->
          let
          (ciphertext_future: t_Slice u8),
          (e_result: Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError) =
            temp_0_
          in
          (Core_models.Slice.impl__len #u8 ciphertext_future <: usize) =.
          (Core_models.Slice.impl__len #u8 ciphertext <: usize))

unfold
let encrypt = encrypt'

assume
val decrypt':
    key: t_Array u8 (mk_usize 32) ->
    plaintext: t_Slice u8 ->
    ciphertext: t_Slice u8 ->
    aad: t_Slice u8 ->
    nonce: t_Array u8 (mk_usize 12)
  -> (t_Slice u8 & Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError)

unfold
let decrypt = decrypt'
