module Securedrop_protocol_minimal.Primitives.Provider.Curve25519
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

assume
val v_SK_LEN': usize

unfold
let v_SK_LEN = v_SK_LEN'

assume
val v_PK_LEN': usize

unfold
let v_PK_LEN = v_PK_LEN'

assume
val v_LEN_DH_SHARE': usize

unfold
let v_LEN_DH_SHARE = v_LEN_DH_SHARE'

assume
val x25519_keygen':
    public_key: t_Array u8 (mk_usize 32) ->
    secret_key: t_Array u8 (mk_usize 32) ->
    randomness: t_Array u8 (mk_usize 32)
  -> (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 32) &
      Core_models.Result.t_Result Prims.unit Libcrux_traits.Kem.Arrayref.t_KeyGenError)

unfold
let x25519_keygen = x25519_keygen'
