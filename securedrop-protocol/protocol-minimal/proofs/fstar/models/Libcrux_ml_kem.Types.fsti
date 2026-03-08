module Libcrux_ml_kem.Types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

///An ML-KEM Ciphertext
type t_MlKemCiphertext (v_SIZE: usize) = { f_value:t_Array u8 v_SIZE }

///An ML-KEM Private key
type t_MlKemPrivateKey (v_SIZE: usize) = { f_value:t_Array u8 v_SIZE }

///An ML-KEM Public key
type t_MlKemPublicKey (v_SIZE: usize) = { f_value:t_Array u8 v_SIZE }
