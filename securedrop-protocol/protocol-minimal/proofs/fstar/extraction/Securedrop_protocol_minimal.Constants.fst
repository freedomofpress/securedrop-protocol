module Securedrop_protocol_minimal.Constants
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let v_LEN_DHKEM_ENCAPS_KEY: usize = Libcrux_curve25519.v_EK_LEN

let v_LEN_DHKEM_DECAPS_KEY: usize = Libcrux_curve25519.v_DK_LEN

let v_LEN_DHKEM_SHAREDSECRET_ENCAPS: usize = Libcrux_curve25519.v_SS_LEN

let v_LEN_DHKEM_SHARED_SECRET: usize = Libcrux_curve25519.v_SS_LEN

let v_LEN_DH_ITEM: usize = v_LEN_DHKEM_DECAPS_KEY

let v_LEN_MLKEM_ENCAPS_KEY: usize = mk_usize 1184

let v_LEN_MLKEM_DECAPS_KEY: usize = mk_usize 2400

let v_LEN_MLKEM_SHAREDSECRET_ENCAPS: usize = mk_usize 1088

let v_LEN_MLKEM_SHAREDSECRET: usize = mk_usize 32

let v_LEN_MLKEM_RAND_SEED_SIZE: usize = mk_usize 64

let v_LEN_XWING_ENCAPS_KEY: usize = mk_usize 1216

let v_LEN_XWING_DECAPS_KEY: usize = mk_usize 32

let v_LEN_XWING_SHAREDSECRET_ENCAPS: usize = mk_usize 1120

let v_LEN_XWING_SHAREDSECRET: usize = mk_usize 32

let v_LEN_XWING_RAND_SEED_SIZE: usize = mk_usize 96

let v_LEN_MESSAGE_ID: usize = mk_usize 16

let v_LEN_KMID: usize =
  (Libcrux_chacha20poly1305.v_TAG_LEN +! Libcrux_chacha20poly1305.v_NONCE_LEN <: usize) +!
  v_LEN_MESSAGE_ID
