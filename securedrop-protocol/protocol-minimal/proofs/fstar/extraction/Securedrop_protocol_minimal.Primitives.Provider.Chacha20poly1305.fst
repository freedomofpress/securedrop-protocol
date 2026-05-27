module Securedrop_protocol_minimal.Primitives.Provider.Chacha20poly1305
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
val v_KEY_LEN': usize

unfold
let v_KEY_LEN = v_KEY_LEN'

assume
val v_NONCE_LEN': usize

unfold
let v_NONCE_LEN = v_NONCE_LEN'

assume
val v_TAG_LEN': usize

unfold
let v_TAG_LEN = v_TAG_LEN'

assume
val encrypt':
    key: t_Array u8 (mk_usize 32) ->
    plaintext: t_Slice u8 ->
    ciphertext: t_Slice u8 ->
    aad: t_Slice u8 ->
    nonce: t_Array u8 (mk_usize 12)
  -> (t_Slice u8 & Core_models.Result.t_Result Prims.unit Libcrux_chacha20poly1305.t_AeadError)

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
