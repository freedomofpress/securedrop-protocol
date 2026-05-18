module Libcrux_chacha20poly1305.Impl_hacl
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let v_NOT_DETACHED: bool = false

val encrypt_checks (ptxt ctxt aad: t_Slice u8) (detached: bool)
    : Prims.Pure
      (t_Slice u8 & Core_models.Result.t_Result (u32 & u32) Libcrux_chacha20poly1305.t_AeadError)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// The ChaCha20-Poly1305 AEAD encryption function. Writes the concatenation of the ciphertext
/// produced by ChaCha20 and the MAC tag into `ctxt` and returns the two pieces separately.
/// This implementation is backed by hacl-rs and can only handle inputs up to a length of `u32::MAX`.
/// When provided longer values, this function will return an error.
val encrypt
      (key: t_Array u8 (mk_usize 32))
      (ptxt ctxt aad: t_Slice u8)
      (nonce: t_Array u8 (mk_usize 12))
    : Prims.Pure
      (Core_models.Result.t_Result (t_Slice u8 & t_Array u8 (mk_usize 16))
          Libcrux_chacha20poly1305.t_AeadError) Prims.l_True (fun _ -> Prims.l_True)

/// The ChaCha20-Poly1305 AEAD decryption function. Writes the result of the decryption to `ptxt`,
/// and returns the slice of appropriate length.
/// This implementation is backed by hacl-rs and can only handle inputs up to a length of `u32::MAX`.
/// When provided longer values, this function will return an error.
val decrypt
      (key: t_Array u8 (mk_usize 32))
      (ptxt ctxt aad: t_Slice u8)
      (nonce: t_Array u8 (mk_usize 12))
    : Prims.Pure
      (t_Slice u8 & Core_models.Result.t_Result (t_Slice u8) Libcrux_chacha20poly1305.t_AeadError)
      Prims.l_True
      (fun _ -> Prims.l_True)
