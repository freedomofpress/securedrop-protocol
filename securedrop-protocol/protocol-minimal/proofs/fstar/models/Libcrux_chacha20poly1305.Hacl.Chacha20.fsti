module Libcrux_chacha20poly1305.Hacl.Chacha20
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let chacha20_constants: t_Array u32 (mk_usize 4) =
  let list = [mk_u32 1634760805; mk_u32 857760878; mk_u32 2036477234; mk_u32 1797285236] in
  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 4);
  Rust_primitives.Hax.array_of_list 4 list

val quarter_round (st: t_Slice u32) (a b c d: u32)
    : Prims.Pure (t_Slice u32) Prims.l_True (fun _ -> Prims.l_True)

val double_round (st: t_Slice u32) : Prims.Pure (t_Slice u32) Prims.l_True (fun _ -> Prims.l_True)

val rounds (st: t_Slice u32) : Prims.Pure (t_Slice u32) Prims.l_True (fun _ -> Prims.l_True)

let chacha20_core__i: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_core__ii_1: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_core__ii_2: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_core__ii_3: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

let chacha20_core__ii_4: u32 = mk_u32 0 +! (mk_u32 4 *! mk_u32 1 <: u32)

let chacha20_core__ii_5: u32 = mk_u32 0 +! (mk_u32 5 *! mk_u32 1 <: u32)

let chacha20_core__ii_6: u32 = mk_u32 0 +! (mk_u32 6 *! mk_u32 1 <: u32)

let chacha20_core__ii_7: u32 = mk_u32 0 +! (mk_u32 7 *! mk_u32 1 <: u32)

let chacha20_core__ii_8: u32 = mk_u32 0 +! (mk_u32 8 *! mk_u32 1 <: u32)

let chacha20_core__ii_9: u32 = mk_u32 0 +! (mk_u32 9 *! mk_u32 1 <: u32)

let chacha20_core__ii_10: u32 = mk_u32 0 +! (mk_u32 10 *! mk_u32 1 <: u32)

let chacha20_core__ii_11: u32 = mk_u32 0 +! (mk_u32 11 *! mk_u32 1 <: u32)

let chacha20_core__ii_12: u32 = mk_u32 0 +! (mk_u32 12 *! mk_u32 1 <: u32)

let chacha20_core__ii_13: u32 = mk_u32 0 +! (mk_u32 13 *! mk_u32 1 <: u32)

let chacha20_core__ii_14: u32 = mk_u32 0 +! (mk_u32 14 *! mk_u32 1 <: u32)

let chacha20_core__ii_15: u32 = mk_u32 0 +! (mk_u32 15 *! mk_u32 1 <: u32)

val chacha20_core (k ctx: t_Slice u32) (ctr: u32)
    : Prims.Pure (t_Slice u32) Prims.l_True (fun _ -> Prims.l_True)

let chacha20_init__i: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_init__ii_1: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_init__ii_2: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_init__ii_3: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

val chacha20_init (ctx: t_Slice u32) (k n: t_Slice u8) (ctr: u32)
    : Prims.Pure Prims.unit Prims.l_True (fun _ -> Prims.l_True)

let chacha20_init__ii_4: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_init__ii_5: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_init__ii_6: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_init__ii_7: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

let chacha20_init__ii_8: u32 = mk_u32 0 +! (mk_u32 4 *! mk_u32 1 <: u32)

let chacha20_init__ii_9: u32 = mk_u32 0 +! (mk_u32 5 *! mk_u32 1 <: u32)

let chacha20_init__ii_10: u32 = mk_u32 0 +! (mk_u32 6 *! mk_u32 1 <: u32)

let chacha20_init__ii_11: u32 = mk_u32 0 +! (mk_u32 7 *! mk_u32 1 <: u32)

let chacha20_init__ii_12: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_init__ii_13: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_init__ii_14: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__i: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_1: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_2: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_3: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_4: u32 = mk_u32 0 +! (mk_u32 4 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_5: u32 = mk_u32 0 +! (mk_u32 5 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_6: u32 = mk_u32 0 +! (mk_u32 6 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_7: u32 = mk_u32 0 +! (mk_u32 7 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_8: u32 = mk_u32 0 +! (mk_u32 8 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_9: u32 = mk_u32 0 +! (mk_u32 9 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_10: u32 = mk_u32 0 +! (mk_u32 10 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_11: u32 = mk_u32 0 +! (mk_u32 11 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_12: u32 = mk_u32 0 +! (mk_u32 12 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_13: u32 = mk_u32 0 +! (mk_u32 13 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_14: u32 = mk_u32 0 +! (mk_u32 14 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_15: u32 = mk_u32 0 +! (mk_u32 15 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_16: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_17: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_18: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_19: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_20: u32 = mk_u32 0 +! (mk_u32 4 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_21: u32 = mk_u32 0 +! (mk_u32 5 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_22: u32 = mk_u32 0 +! (mk_u32 6 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_23: u32 = mk_u32 0 +! (mk_u32 7 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_24: u32 = mk_u32 0 +! (mk_u32 8 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_25: u32 = mk_u32 0 +! (mk_u32 9 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_26: u32 = mk_u32 0 +! (mk_u32 10 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_27: u32 = mk_u32 0 +! (mk_u32 11 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_28: u32 = mk_u32 0 +! (mk_u32 12 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_29: u32 = mk_u32 0 +! (mk_u32 13 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_30: u32 = mk_u32 0 +! (mk_u32 14 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_31: u32 = mk_u32 0 +! (mk_u32 15 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_32: u32 = mk_u32 0 +! (mk_u32 0 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_33: u32 = mk_u32 0 +! (mk_u32 1 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_34: u32 = mk_u32 0 +! (mk_u32 2 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_35: u32 = mk_u32 0 +! (mk_u32 3 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_36: u32 = mk_u32 0 +! (mk_u32 4 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_37: u32 = mk_u32 0 +! (mk_u32 5 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_38: u32 = mk_u32 0 +! (mk_u32 6 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_39: u32 = mk_u32 0 +! (mk_u32 7 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_40: u32 = mk_u32 0 +! (mk_u32 8 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_41: u32 = mk_u32 0 +! (mk_u32 9 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_42: u32 = mk_u32 0 +! (mk_u32 10 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_43: u32 = mk_u32 0 +! (mk_u32 11 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_44: u32 = mk_u32 0 +! (mk_u32 12 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_45: u32 = mk_u32 0 +! (mk_u32 13 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_46: u32 = mk_u32 0 +! (mk_u32 14 *! mk_u32 1 <: u32)

let chacha20_encrypt_block__ii_47: u32 = mk_u32 0 +! (mk_u32 15 *! mk_u32 1 <: u32)

val chacha20_encrypt_block (ctx: t_Slice u32) (out: t_Slice u8) (incr: u32) (text: t_Slice u8)
    : Prims.Pure (t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)

val chacha20_encrypt_last
      (ctx: t_Slice u32)
      (len: u32)
      (out: t_Slice u8)
      (incr: u32)
      (text: t_Slice u8)
    : Prims.Pure (t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)

val chacha20_update (ctx: t_Slice u32) (len: u32) (out text: t_Slice u8)
    : Prims.Pure (t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)

val chacha20_encrypt (len: u32) (out text key n: t_Slice u8) (ctr: u32)
    : Prims.Pure (t_Slice u8) Prims.l_True (fun _ -> Prims.l_True)
