module Hpke_rs_crypto.Types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_KemAlgorithm =
  | KemAlgorithm_DhKemP256 : t_KemAlgorithm
  | KemAlgorithm_DhKemP384 : t_KemAlgorithm
  | KemAlgorithm_DhKemP521 : t_KemAlgorithm
  | KemAlgorithm_DhKem25519 : t_KemAlgorithm
  | KemAlgorithm_DhKem448 : t_KemAlgorithm
  | KemAlgorithm_XWingDraft06 : t_KemAlgorithm

type t_KdfAlgorithm =
  | KdfAlgorithm_HkdfSha256 : t_KdfAlgorithm
  | KdfAlgorithm_HkdfSha384 : t_KdfAlgorithm
  | KdfAlgorithm_HkdfSha512 : t_KdfAlgorithm

type t_AeadAlgorithm =
  | AeadAlgorithm_Aes128Gcm : t_AeadAlgorithm
  | AeadAlgorithm_Aes256Gcm : t_AeadAlgorithm
  | AeadAlgorithm_ChaCha20Poly1305 : t_AeadAlgorithm
  | AeadAlgorithm_HpkeExport : t_AeadAlgorithm
