module Libcrux_chacha20poly1305.Hacl.Aead_chacha20poly1305
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

val poly1305_padded_32_ (ctx: t_Slice u64) (len: u32) (text: t_Slice u8)
    : Prims.Pure Prims.unit Prims.l_True (fun _ -> Prims.l_True)

val poly1305_do_32_ (k: t_Slice u8) (aadlen: u32) (aad: t_Slice u8) (mlen: u32) (m out: t_Slice u8)
    : Prims.Pure Prims.unit Prims.l_True (fun _ -> Prims.l_True)

(**
Encrypt a message `input` with key `key`.

The arguments `key`, `nonce`, `data`, and `data_len` are same in encryption/decryption.
Note: Encryption and decryption can be executed in-place, i.e., `input` and `output` can point to the same memory.

@param output Pointer to `input_len` bytes of memory where the ciphertext is written to.
@param tag Pointer to 16 bytes of memory where the mac is written to.
@param input Pointer to `input_len` bytes of memory where the message is read from.
@param input_len Length of the message.
@param data Pointer to `data_len` bytes of memory where the associated data is read from.
@param data_len Length of the associated data.
@param key Pointer to 32 bytes of memory where the AEAD key is read from.
@param nonce Pointer to 12 bytes of memory where the AEAD nonce is read from.
*)
val encrypt
      (output tag input: t_Slice u8)
      (input_len: u32)
      (data: t_Slice u8)
      (data_len: u32)
      (key nonce: t_Slice u8)
    : Prims.Pure (t_Slice u8 & t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)

let decrypt__i: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let decrypt__ii_1: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let decrypt__ii_2: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let decrypt__ii_3: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

let decrypt__ii_4: u32 = mk_u32 0 +! (mk_u32 4 *! mk_u32 1 <: u32)

let decrypt__ii_5: u32 = mk_u32 0 +! (mk_u32 5 *! mk_u32 1 <: u32)

let decrypt__ii_6: u32 = mk_u32 0 +! (mk_u32 6 *! mk_u32 1 <: u32)

let decrypt__ii_7: u32 = mk_u32 0 +! (mk_u32 7 *! mk_u32 1 <: u32)

let decrypt__ii_8: u32 = mk_u32 0 +! (mk_u32 8 *! mk_u32 1 <: u32)

let decrypt__ii_9: u32 = mk_u32 0 +! (mk_u32 9 *! mk_u32 1 <: u32)

let decrypt__ii_10: u32 = mk_u32 0 +! (mk_u32 10 *! mk_u32 1 <: u32)

let decrypt__ii_11: u32 = mk_u32 0 +! (mk_u32 11 *! mk_u32 1 <: u32)

let decrypt__ii_12: u32 = mk_u32 0 +! (mk_u32 12 *! mk_u32 1 <: u32)

let decrypt__ii_13: u32 = mk_u32 0 +! (mk_u32 13 *! mk_u32 1 <: u32)

let decrypt__ii_14: u32 = mk_u32 0 +! (mk_u32 14 *! mk_u32 1 <: u32)

let decrypt__ii_15: u32 = mk_u32 0 +! (mk_u32 15 *! mk_u32 1 <: u32)

(**
Decrypt a ciphertext `input` with key `key`.

The arguments `key`, `nonce`, `data`, and `data_len` are same in encryption/decryption.
Note: Encryption and decryption can be executed in-place, i.e., `output` and `input` can point to the same memory.

If decryption succeeds, the resulting plaintext is stored in `output` and the function returns the success code 0.
If decryption fails, the array `output` remains unchanged and the function returns the error code 1.

@param output Pointer to `input_len` bytes of memory where the message is written to.
@param input Pointer to `input_len` bytes of memory where the ciphertext is read from.
@param input_len Length of the ciphertext.
@param data Pointer to `data_len` bytes of memory where the associated data is read from.
@param data_len Length of the associated data.
@param key Pointer to 32 bytes of memory where the AEAD key is read from.
@param nonce Pointer to 12 bytes of memory where the AEAD nonce is read from.
@param tag Pointer to 16 bytes of memory where the mac is read from.

@returns 0 on succeess; 1 on failure.
*)
val decrypt
      (output input: t_Slice u8)
      (input_len: u32)
      (data: t_Slice u8)
      (data_len: u32)
      (key nonce tag: t_Slice u8)
    : Prims.Pure (t_Slice u8 & u32) Prims.l_True (fun _ -> Prims.l_True)
