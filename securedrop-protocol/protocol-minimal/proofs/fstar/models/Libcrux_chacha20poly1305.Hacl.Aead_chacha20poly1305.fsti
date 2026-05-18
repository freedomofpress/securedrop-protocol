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
