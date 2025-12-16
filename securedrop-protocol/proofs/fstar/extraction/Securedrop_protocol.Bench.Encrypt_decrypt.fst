module Securedrop_protocol.Bench.Encrypt_decrypt
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Getrandom.Error in
  let open Hpke_rs in
  let open Hpke_rs_crypto in
  let open Hpke_rs_libcrux in
  let open Libcrux_ml_kem.Mlkem768 in
  let open Libcrux_traits.Kem.Arrayref in
  let open Libcrux_traits.Kem.Owned in
  let open Rand_chacha.Chacha in
  let open Rand_core in
  let open Securedrop_protocol.Primitives.X25519 in
  ()

let v_HPKE_PSK_ID: t_Slice u8 =
  (let list =
      [
        mk_u8 80; mk_u8 83; mk_u8 75; mk_u8 95; mk_u8 73; mk_u8 78; mk_u8 70; mk_u8 79; mk_u8 95;
        mk_u8 73; mk_u8 68; mk_u8 95; mk_u8 84; mk_u8 65; mk_u8 71
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 15);
    Rust_primitives.Hax.array_of_list 15 list)
  <:
  t_Slice u8

let v_HPKE_AAD: t_Slice u8 =
  (let list:Prims.list u8 = [] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
    Rust_primitives.Hax.array_of_list 0 list)
  <:
  t_Slice u8

let v_HPKE_BASE_INFO: t_Slice u8 =
  (let list:Prims.list u8 = [] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
    Rust_primitives.Hax.array_of_list 0 list)
  <:
  t_Slice u8

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

type t_CombinedCiphertext = {
  f_ct_message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_message_dhakem_ss_encap:t_Array u8 (mk_usize 32);
  f_message_pqpsk_ss_encap:t_Array u8 (mk_usize 1088)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Core_models.Fmt.t_Debug t_CombinedCiphertext

unfold
let impl_10 = impl_10'

let impl_11: Core_models.Clone.t_Clone t_CombinedCiphertext =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_CombinedCiphertext__to_bytes (self: t_CombinedCiphertext)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (self.f_message_dhakem_ss_encap <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (self.f_message_pqpsk_ss_encap <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          self.f_ct_message
        <:
        t_Slice u8)
  in
  buf

let impl_CombinedCiphertext__len (self: t_CombinedCiphertext) : usize =
  Alloc.Vec.impl_1__len #u8
    #Alloc.Alloc.t_Global
    (impl_CombinedCiphertext__to_bytes self <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)

let impl_CombinedCiphertext__from_bytes (ct_bytes: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Core_models.Result.t_Result t_CombinedCiphertext Anyhow.t_Error =
  let (dhakem_ss_encaps: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let (pqpsk_ss_encaps: t_Array u8 (mk_usize 1088)):t_Array u8 (mk_usize 1088) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1088)
  in
  let dhakem_ss_encaps:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      dhakem_ss_encaps
      (ct_bytes.[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = v_LEN_DHKEM_SHAREDSECRET_ENCAPS
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let pqpsk_ss_encaps:t_Array u8 (mk_usize 1088) =
    Core_models.Slice.impl__copy_from_slice #u8
      pqpsk_ss_encaps
      (ct_bytes.[ {
            Core_models.Ops.Range.f_start = v_LEN_DHKEM_SHAREDSECRET_ENCAPS;
            Core_models.Ops.Range.f_end
            =
            v_LEN_DHKEM_SHAREDSECRET_ENCAPS +! v_LEN_MLKEM_SHAREDSECRET_ENCAPS <: usize
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let (cmessage: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global):Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec #u8
      (ct_bytes.[ {
            Core_models.Ops.Range.f_start
            =
            v_LEN_DHKEM_SHAREDSECRET_ENCAPS +! v_LEN_MLKEM_SHAREDSECRET_ENCAPS <: usize
          }
          <:
          Core_models.Ops.Range.t_RangeFrom usize ]
        <:
        t_Slice u8)
  in
  Core_models.Result.Result_Ok
  ({
      f_ct_message = cmessage;
      f_message_dhakem_ss_encap = dhakem_ss_encaps;
      f_message_pqpsk_ss_encap = pqpsk_ss_encaps
    }
    <:
    t_CombinedCiphertext)
  <:
  Core_models.Result.t_Result t_CombinedCiphertext Anyhow.t_Error

type t_Envelope = {
  f_cmessage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_cmetadata:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_metadata_encap:t_Array u8 (mk_usize 1120);
  f_mgdh_pubkey:t_Array u8 (mk_usize 32);
  f_mgdh:t_Array u8 (mk_usize 32)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Core_models.Fmt.t_Debug t_Envelope

unfold
let impl_12 = impl_12'

let impl_13: Core_models.Clone.t_Clone t_Envelope =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

type t_Plaintext = {
  f_recipient_pubkey_dhakem:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_sender_reply_pubkey_dhakem:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_sender_reply_pubkey_pq_psk:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_sender_reply_pubkey_hybrid:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_sender_fetch_key:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_msg:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Core_models.Fmt.t_Debug t_Plaintext

unfold
let impl_14 = impl_14'

/// Represent stored ciphertexts on the server
type t_ServerMessageStore = {
  f_message_id:t_Array u8 (mk_usize 16);
  f_envelope:t_Envelope
}

type t_FetchResponse = {
  f_enc_id:t_Array u8 (mk_usize 44);
  f_pmgdh:t_Array u8 (mk_usize 32)
}

let impl_FetchResponse__new (enc_id: t_Array u8 (mk_usize 44)) (pmgdh: t_Array u8 (mk_usize 32))
    : t_FetchResponse = { f_enc_id = enc_id; f_pmgdh = pmgdh } <: t_FetchResponse

let impl_Plaintext__as_bytes (self: t_Plaintext) : t_Slice u8 =
  Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_msg

let impl_Plaintext__len (self: t_Plaintext) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_msg

let impl_Plaintext__into_bytes (self: t_Plaintext) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  self.f_msg

let impl_Envelope__size_hint (self: t_Envelope) : usize =
  (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_cmessage <: usize) +!
  (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_cmetadata <: usize)

let impl_Envelope__cmessage_len (self: t_Envelope) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_cmessage

let impl_Envelope__cmetadata_len (self: t_Envelope) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_cmetadata

let impl_ServerMessageStore__new (message_id: t_Array u8 (mk_usize 16)) (envelope: t_Envelope)
    : t_ServerMessageStore =
  { f_message_id = message_id; f_envelope = envelope } <: t_ServerMessageStore

let impl_ServerMessageStore__message_id (self: t_ServerMessageStore) : t_Array u8 (mk_usize 16) =
  self.f_message_id

let impl_ServerMessageStore__envelope (self: t_ServerMessageStore) : t_Envelope = self.f_envelope

type t_KeyBundle = {
  f_dhakem_sk:t_Array u8 (mk_usize 32);
  f_dhakem_pk:t_Array u8 (mk_usize 32);
  f_pq_kem_psk_sk:t_Array u8 (mk_usize 2400);
  f_pq_kem_psk_pk:t_Array u8 (mk_usize 1184);
  f_hybrid_md_sk:t_Array u8 (mk_usize 32);
  f_hybrid_md_pk:t_Array u8 (mk_usize 1216)
}

let impl_KeyBundle__get_dhakem_sk (self: t_KeyBundle) : t_Array u8 (mk_usize 32) = self.f_dhakem_sk

let impl_KeyBundle__get_dhakem_pk (self: t_KeyBundle) : t_Array u8 (mk_usize 32) = self.f_dhakem_pk

let impl_KeyBundle__get_pq_kem_psk_pk (self: t_KeyBundle) : t_Array u8 (mk_usize 1184) =
  self.f_pq_kem_psk_pk

let impl_KeyBundle__get_pq_kem_psk_sk (self: t_KeyBundle) : t_Array u8 (mk_usize 2400) =
  self.f_pq_kem_psk_sk

let impl_KeyBundle__get_hybrid_md_pk (self: t_KeyBundle) : t_Array u8 (mk_usize 1216) =
  self.f_hybrid_md_pk

let impl_KeyBundle__get_hybrid_md_sk (self: t_KeyBundle) : t_Array u8 (mk_usize 32) =
  self.f_hybrid_md_sk

class t_User (v_Self: Type0) = {
  f_keybundle_pre:v_Self -> Core_models.Option.t_Option usize -> Type0;
  f_keybundle_post:v_Self -> Core_models.Option.t_Option usize -> t_KeyBundle -> Type0;
  f_keybundle:x0: v_Self -> x1: Core_models.Option.t_Option usize
    -> Prims.Pure t_KeyBundle (f_keybundle_pre x0 x1) (fun result -> f_keybundle_post x0 x1 result);
  f_get_fetch_sk_pre:v_Self -> Type0;
  f_get_fetch_sk_post:v_Self -> t_Array u8 (mk_usize 32) -> Type0;
  f_get_fetch_sk:x0: v_Self
    -> Prims.Pure (t_Array u8 (mk_usize 32))
        (f_get_fetch_sk_pre x0)
        (fun result -> f_get_fetch_sk_post x0 result);
  f_get_fetch_pk_pre:v_Self -> Type0;
  f_get_fetch_pk_post:v_Self -> t_Array u8 (mk_usize 32) -> Type0;
  f_get_fetch_pk:x0: v_Self
    -> Prims.Pure (t_Array u8 (mk_usize 32))
        (f_get_fetch_pk_pre x0)
        (fun result -> f_get_fetch_pk_post x0 result);
  f_get_all_keys_pre:v_Self -> Type0;
  f_get_all_keys_post:v_Self -> t_Slice t_KeyBundle -> Type0;
  f_get_all_keys:x0: v_Self
    -> Prims.Pure (t_Slice t_KeyBundle)
        (f_get_all_keys_pre x0)
        (fun result -> f_get_all_keys_post x0 result)
}

let hpke_keypair_from_bytes (sk_bytes pk_bytes: t_Slice u8) : Hpke_rs.t_HpkeKeyPair =
  Core_models.Convert.f_from #Hpke_rs.t_HpkeKeyPair
    #(t_Slice u8 & t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (sk_bytes, pk_bytes <: (t_Slice u8 & t_Slice u8))

let hpke_pubkey_from_bytes (pk_bytes: t_Slice u8) : Hpke_rs.t_HpkePublicKey =
  Core_models.Convert.f_from #Hpke_rs.t_HpkePublicKey
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    pk_bytes

let encrypt
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (sender: dyn 1 (fun z -> t_User z))
      (plaintext: t_Slice u8)
      (recipient: dyn 1 (fun z -> t_User z))
      (recipient_bundle_index: Core_models.Option.t_Option usize)
    : (v_R & t_Envelope) =
  let (hpke_authenc: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux):Hpke_rs.t_Hpke
  Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_AuthPsk <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_DhKem25519 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_ChaCha20Poly1305 <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let (hpke_metadata: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux):Hpke_rs.t_Hpke
  Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_Base <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_XWingDraft06 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_ChaCha20Poly1305 <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let recipient_keybundle:t_KeyBundle =
    f_keybundle #(dyn 1 (fun z -> t_User z))
      #FStar.Tactics.Typeclasses.solve
      recipient
      recipient_bundle_index
  in
  let sender_keys:t_KeyBundle =
    f_keybundle #(dyn 1 (fun z -> t_User z))
      #FStar.Tactics.Typeclasses.solve
      sender
      (Core_models.Option.Option_None <: Core_models.Option.t_Option usize)
  in
  let recipient_dhakem_pubkey:Hpke_rs.t_HpkePublicKey =
    hpke_pubkey_from_bytes (impl_KeyBundle__get_dhakem_pk recipient_keybundle <: t_Slice u8)
  in
  let sender_hpke_keypair:Hpke_rs.t_HpkeKeyPair =
    hpke_keypair_from_bytes (impl_KeyBundle__get_dhakem_sk sender_keys <: t_Slice u8)
      (impl_KeyBundle__get_dhakem_pk sender_keys <: t_Slice u8)
  in
  let (randomness: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  let (psk: t_Array u8 (mk_usize 32)), (psk_ct: t_Array u8 (mk_usize 1088)) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 1088))
      #Libcrux_traits.Kem.Arrayref.t_EncapsError
      (Libcrux_traits.Kem.Owned.f_encaps #Libcrux_ml_kem.Mlkem768.t_MlKem768 #(mk_usize 1184)
          #(mk_usize 2400) #(mk_usize 1088) #(mk_usize 32) #(mk_usize 64) #(mk_usize 32)
          #FStar.Tactics.Typeclasses.solve
          (impl_KeyBundle__get_pq_kem_psk_pk recipient_keybundle <: t_Array u8 (mk_usize 1184))
          randomness
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 1088))
          Libcrux_traits.Kem.Arrayref.t_EncapsError)
      "PSK encaps failed"
  in
  let
  (tmp0: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux),
  (out:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Hpke_rs.t_HpkeError) =
    Hpke_rs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
      hpke_authenc
      recipient_dhakem_pubkey
      (psk_ct <: t_Slice u8)
      v_HPKE_AAD
      plaintext
      (Core_models.Option.Option_Some (psk <: t_Slice u8)
        <:
        Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_Some v_HPKE_PSK_ID <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_Some
        (Hpke_rs.impl_HpkeKeyPair__private_key sender_hpke_keypair <: Hpke_rs.t_HpkePrivateKey)
        <:
        Core_models.Option.t_Option Hpke_rs.t_HpkePrivateKey)
  in
  let hpke_authenc:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux = tmp0 in
  let
  (mesage_dhakem_shared_secret_encaps: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global),
  (message_ciphertext: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Result.impl__unwrap #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      out
  in
  let (dhakem_ss_encaps_bytes: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let dhakem_ss_encaps_bytes:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      dhakem_ss_encaps_bytes
      (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global mesage_dhakem_shared_secret_encaps
        <:
        t_Slice u8)
  in
  let (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let (eph_sk: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      out
      "DH keygen (ephemeral fetch) failed!"
  in
  let (eph_pk: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let eph_pk:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public eph_pk eph_sk
  in
  let mgdh:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let mgdh:t_Array u8 (mk_usize 32) =
    Libcrux_hacl_rs.Curve25519_51_.scalarmult mgdh
      (eph_sk <: t_Slice u8)
      (f_get_fetch_pk #(dyn 1 (fun z -> t_User z)) #FStar.Tactics.Typeclasses.solve recipient
        <:
        t_Slice u8)
  in
  let (sender_pubkey_bytes: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let sender_pubkey_bytes:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      sender_pubkey_bytes
      (Hpke_rs.impl_HpkePublicKey__as_slice (Hpke_rs.impl_HpkeKeyPair__public_key sender_hpke_keypair

            <:
            Hpke_rs.t_HpkePublicKey)
        <:
        t_Slice u8)
  in
  let recipient_md_pubkey:Hpke_rs.t_HpkePublicKey =
    hpke_pubkey_from_bytes (impl_KeyBundle__get_hybrid_md_pk recipient_keybundle <: t_Slice u8)
  in
  let
  (tmp0: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux),
  (out:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Hpke_rs.t_HpkeError) =
    Hpke_rs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
      hpke_metadata
      recipient_md_pubkey
      v_HPKE_BASE_INFO
      v_HPKE_AAD
      (sender_pubkey_bytes <: t_Slice u8)
      (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_None <: Core_models.Option.t_Option Hpke_rs.t_HpkePrivateKey)
  in
  let hpke_metadata:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux = tmp0 in
  let
  (md_ss_encaps_vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global),
  (metadata_ciphertext: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Result.impl__expect #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      out
      "Expected Hpke.BaseMode sealed ciphertext"
  in
  let args:usize = v_LEN_XWING_SHAREDSECRET_ENCAPS <: usize in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let (metadata_ss_encaps: t_Array u8 (mk_usize 1120)):t_Array u8 (mk_usize 1120) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 1120))
      #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #(t_Array u8 (mk_usize 1120))
          #FStar.Tactics.Typeclasses.solve
          md_ss_encaps_vec
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 1120))
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                      (mk_usize 1)
                      (let list = ["Need "; " byte encapsulated shared secret"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                        Rust_primitives.Hax.array_of_list 2 list)
                      args
                    <:
                    Core_models.Fmt.t_Arguments)
                <:
                Alloc.String.t_String)
            <:
            Alloc.String.t_String)
        <:
        string)
  in
  let cmessage:t_CombinedCiphertext =
    {
      f_ct_message = message_ciphertext;
      f_message_dhakem_ss_encap = dhakem_ss_encaps_bytes;
      f_message_pqpsk_ss_encap = psk_ct
    }
    <:
    t_CombinedCiphertext
  in
  let hax_temp_output:t_Envelope =
    {
      f_cmessage = impl_CombinedCiphertext__to_bytes cmessage;
      f_cmetadata = metadata_ciphertext;
      f_metadata_encap = metadata_ss_encaps;
      f_mgdh_pubkey = eph_pk;
      f_mgdh = mgdh
    }
    <:
    t_Envelope
  in
  rng, hax_temp_output <: (v_R & t_Envelope)

let decrypt (receiver: dyn 1 (fun z -> t_User z)) (envelope: t_Envelope) : t_Plaintext =
  let (hpke_authenc: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux):Hpke_rs.t_Hpke
  Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_AuthPsk <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_DhKem25519 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_ChaCha20Poly1305 <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let (hpke_base: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux):Hpke_rs.t_Hpke
  Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_Base <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_XWingDraft06 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_ChaCha20Poly1305 <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let
  (results: Alloc.Vec.t_Vec (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
    (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Filter_map.t_FilterMap
          (Core_models.Iter.Adapters.Enumerate.t_Enumerate
            (Core_models.Slice.Iter.t_Iter t_KeyBundle))
          ((usize & t_KeyBundle)
              -> Core_models.Option.t_Option (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)))
      #FStar.Tactics.Typeclasses.solve
      #(Alloc.Vec.t_Vec (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
      (Core_models.Iter.Traits.Iterator.f_filter_map #(Core_models.Iter.Adapters.Enumerate.t_Enumerate
            (Core_models.Slice.Iter.t_Iter t_KeyBundle))
          #FStar.Tactics.Typeclasses.solve
          #(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          (Core_models.Iter.Traits.Iterator.f_enumerate #(Core_models.Slice.Iter.t_Iter t_KeyBundle)
              #FStar.Tactics.Typeclasses.solve
              (Core_models.Slice.impl__iter #t_KeyBundle
                  (f_get_all_keys #(dyn 1 (fun z -> t_User z))
                      #FStar.Tactics.Typeclasses.solve
                      receiver
                    <:
                    t_Slice t_KeyBundle)
                <:
                Core_models.Slice.Iter.t_Iter t_KeyBundle)
            <:
            Core_models.Iter.Adapters.Enumerate.t_Enumerate
            (Core_models.Slice.Iter.t_Iter t_KeyBundle))
          (fun temp_0_ ->
              let (i: usize), (bundle: t_KeyBundle) = temp_0_ in
              let receiver_metadata_keypair:Hpke_rs.t_HpkeKeyPair =
                hpke_keypair_from_bytes (impl_KeyBundle__get_hybrid_md_sk bundle <: t_Slice u8)
                  (impl_KeyBundle__get_hybrid_md_pk bundle <: t_Slice u8)
              in
              let receiver_dhakem_keypair:Hpke_rs.t_HpkeKeyPair =
                hpke_keypair_from_bytes (impl_KeyBundle__get_dhakem_sk bundle <: t_Slice u8)
                  (impl_KeyBundle__get_dhakem_pk bundle <: t_Slice u8)
              in
              Core_models.Option.impl__map #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                (Core_models.Result.impl__ok #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #Hpke_rs.t_HpkeError
                    (Hpke_rs.impl_7__open #Hpke_rs_libcrux.t_HpkeLibcrux hpke_base
                        (envelope.f_metadata_encap <: t_Slice u8)
                        (Hpke_rs.impl_HpkeKeyPair__private_key receiver_metadata_keypair
                          <:
                          Hpke_rs.t_HpkePrivateKey) v_HPKE_BASE_INFO v_HPKE_AAD
                        (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            #FStar.Tactics.Typeclasses.solve
                            envelope.f_cmetadata
                          <:
                          t_Slice u8)
                        (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
                        (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
                        (Core_models.Option.Option_None
                          <:
                          Core_models.Option.t_Option Hpke_rs.t_HpkePublicKey)
                      <:
                      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                        Hpke_rs.t_HpkeError)
                  <:
                  Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                (fun decrypted_metadata ->
                    let decrypted_metadata:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                      decrypted_metadata
                    in
                    i, decrypted_metadata <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)))
        <:
        Core_models.Iter.Adapters.Filter_map.t_FilterMap
          (Core_models.Iter.Adapters.Enumerate.t_Enumerate
            (Core_models.Slice.Iter.t_Iter t_KeyBundle))
          ((usize & t_KeyBundle)
              -> Core_models.Option.t_Option (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)))
  in
  let _:Prims.unit =
    match
      Alloc.Vec.impl_1__len #(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #Alloc.Alloc.t_Global
        results,
      mk_usize 1
      <:
      (usize & usize)
    with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let (index: usize), (raw_metadata: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Option.impl__unwrap #(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (Core_models.Slice.impl__first #(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
                  (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              results
            <:
            t_Slice (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
        <:
        Core_models.Option.t_Option (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
  in
  let receiver_keys:t_KeyBundle =
    f_keybundle #(dyn 1 (fun z -> t_User z))
      #FStar.Tactics.Typeclasses.solve
      receiver
      (Core_models.Option.Option_Some index <: Core_models.Option.t_Option usize)
  in
  let (raw_md_bytes: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
      #Core_models.Array.t_TryFromSliceError
      (Core_models.Convert.f_try_into #(t_Slice u8)
          #(t_Array u8 (mk_usize 32))
          #FStar.Tactics.Typeclasses.solve
          (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global raw_metadata <: t_Slice u8)
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Core_models.Array.t_TryFromSliceError
      )
      "Need {DH_AKEM_PUBLIC_KEY_LEN} array"
  in
  let hpke_pubkey_sender:Hpke_rs.t_HpkePublicKey =
    hpke_pubkey_from_bytes (raw_md_bytes <: t_Slice u8)
  in
  let hpke_receiver_keys:Hpke_rs.t_HpkeKeyPair =
    hpke_keypair_from_bytes (impl_KeyBundle__get_dhakem_sk receiver_keys <: t_Slice u8)
      (impl_KeyBundle__get_dhakem_pk receiver_keys <: t_Slice u8)
  in
  let combined_ct:t_CombinedCiphertext =
    Core_models.Result.impl__unwrap #t_CombinedCiphertext
      #Anyhow.t_Error
      (impl_CombinedCiphertext__from_bytes envelope.f_cmessage
        <:
        Core_models.Result.t_Result t_CombinedCiphertext Anyhow.t_Error)
  in
  let psk:t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__unwrap #(t_Array u8 (mk_usize 32))
      #Libcrux_traits.Kem.Arrayref.t_DecapsError
      (Libcrux_traits.Kem.Owned.f_decaps #Libcrux_ml_kem.Mlkem768.t_MlKem768 #(mk_usize 1184)
          #(mk_usize 2400) #(mk_usize 1088) #(mk_usize 32) #(mk_usize 64) #(mk_usize 32)
          #FStar.Tactics.Typeclasses.solve combined_ct.f_message_pqpsk_ss_encap
          (impl_KeyBundle__get_pq_kem_psk_sk receiver_keys <: t_Array u8 (mk_usize 2400))
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
          Libcrux_traits.Kem.Arrayref.t_DecapsError)
  in
  let pt:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Core_models.Result.impl__expect #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      (Hpke_rs.impl_7__open #Hpke_rs_libcrux.t_HpkeLibcrux hpke_authenc
          (combined_ct.f_message_dhakem_ss_encap <: t_Slice u8)
          (Hpke_rs.impl_HpkeKeyPair__private_key hpke_receiver_keys <: Hpke_rs.t_HpkePrivateKey)
          (combined_ct.f_message_pqpsk_ss_encap <: t_Slice u8) v_HPKE_AAD
          (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              combined_ct.f_ct_message
            <:
            t_Slice u8)
          (Core_models.Option.Option_Some (psk <: t_Slice u8)
            <:
            Core_models.Option.t_Option (t_Slice u8))
          (Core_models.Option.Option_Some v_HPKE_PSK_ID <: Core_models.Option.t_Option (t_Slice u8))
          (Core_models.Option.Option_Some hpke_pubkey_sender
            <:
            Core_models.Option.t_Option Hpke_rs.t_HpkePublicKey)
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hpke_rs.t_HpkeError)
      "Decryption failed"
  in
  {
    f_msg = pt;
    f_recipient_pubkey_dhakem
    =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
    f_sender_reply_pubkey_dhakem
    =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
    f_sender_reply_pubkey_pq_psk
    =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
    f_sender_reply_pubkey_hybrid
    =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
    f_sender_fetch_key
    =
    Core_models.Option.Option_None
    <:
    Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }
  <:
  t_Plaintext

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid (ServerMessageStore),
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
let compute_fetch_challenges
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (store: t_Slice t_ServerMessageStore)
      (total_responses: usize)
    : (v_R & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #t_FetchResponse total_responses
  in
  let
  (eph_sk: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (e_eph_pk: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
          "securedrop_protocol::primitives::x25519::generate_dh_keypair::<&mut R>(&mut (rng))"
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "Wanted DH keypair"
  in
  let eph_sk_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__into_bytes (Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
          #FStar.Tactics.Typeclasses.solve
          eph_sk
        <:
        Securedrop_protocol.Primitives.X25519.t_DHPrivateKey)
  in
  let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
    Rust_primitives.Hax.Folds.fold_cf (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            t_ServerMessageStore)
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #t_ServerMessageStore store
            <:
            Core_models.Slice.Iter.t_Iter t_ServerMessageStore)
        <:
        Core_models.Slice.Iter.t_Iter t_ServerMessageStore)
      responses
      (fun responses entry ->
          let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global = responses in
          let entry:t_ServerMessageStore = entry in
          let message_id:t_Array u8 (mk_usize 16) = entry.f_message_id in
          let (shared_secret: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
          in
          let shared_secret:t_Array u8 (mk_usize 32) =
            Libcrux_hacl_rs.Curve25519_51_.scalarmult shared_secret
              (eph_sk_bytes <: t_Slice u8)
              (entry.f_envelope.f_mgdh <: t_Slice u8)
          in
          let enc_mid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Core_models.Result.impl__unwrap #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #Anyhow.t_Error
              (Securedrop_protocol.Primitives.encrypt_message_id (shared_secret <: t_Slice u8)
                  (message_id <: t_Slice u8)
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
              )
          in
          let args:usize = v_LEN_KMID <: usize in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          let kmid:t_Array u8 (mk_usize 44) =
            Core_models.Result.impl__expect #(t_Array u8 (mk_usize 44))
              #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #(t_Array u8 (mk_usize 44))
                  #FStar.Tactics.Typeclasses.solve
                  enc_mid
                <:
                Core_models.Result.t_Result (t_Array u8 (mk_usize 44))
                  (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
                  #FStar.Tactics.Typeclasses.solve
                  (Core_models.Hint.must_use #Alloc.String.t_String
                      (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                              (mk_usize 1)
                              (let list = ["Need "; " bytes"] in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                                Rust_primitives.Hax.array_of_list 2 list)
                              args
                            <:
                            Core_models.Fmt.t_Arguments)
                        <:
                        Alloc.String.t_String)
                    <:
                    Alloc.String.t_String)
                <:
                string)
          in
          let (pmgdh: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
          in
          let pmgdh:t_Array u8 (mk_usize 32) =
            Libcrux_hacl_rs.Curve25519_51_.scalarmult pmgdh
              (eph_sk_bytes <: t_Slice u8)
              (entry.f_envelope.f_mgdh_pubkey <: t_Slice u8)
          in
          let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
              ({ f_enc_id = kmid; f_pmgdh = pmgdh } <: t_FetchResponse)
          in
          if
            (Alloc.Vec.impl_1__len #t_FetchResponse #Alloc.Alloc.t_Global responses <: usize) =.
            total_responses
          then
            Core_models.Ops.Control_flow.ControlFlow_Break
            ((), responses <: (Prims.unit & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global))
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Prims.unit & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)
              (Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)
          else
            Core_models.Ops.Control_flow.ControlFlow_Continue responses
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Prims.unit & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)
              (Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global))
  in
  let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
    Rust_primitives.Hax.while_loop (fun temp_0_ ->
          let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          true)
      (fun temp_0_ ->
          let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          (Alloc.Vec.impl_1__len #t_FetchResponse #Alloc.Alloc.t_Global responses <: usize) <.
          total_responses
          <:
          bool)
      (fun temp_0_ ->
          let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
      (responses, rng <: (Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global & v_R))
      (fun temp_0_ ->
          let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          let (pad_kmid: t_Array u8 (mk_usize 44)):t_Array u8 (mk_usize 44) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 44)
          in
          let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 44)) =
            Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng pad_kmid
          in
          let rng:v_R = tmp0 in
          let pad_kmid:t_Array u8 (mk_usize 44) = tmp1 in
          let _:Prims.unit = () in
          let (pad_pmgdh: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
          in
          let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
            Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng pad_pmgdh
          in
          let rng:v_R = tmp0 in
          let pad_pmgdh:t_Array u8 (mk_usize 32) = tmp1 in
          let _:Prims.unit = () in
          let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_FetchResponse
              #Alloc.Alloc.t_Global
              responses
              ({ f_enc_id = pad_kmid; f_pmgdh = pad_pmgdh } <: t_FetchResponse)
          in
          responses, rng <: (Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global & v_R))
  in
  let hax_temp_output:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global = responses in
  rng, hax_temp_output <: (v_R & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)

/// Solve fetch challenges (encrypted message IDs) and return array of valid message_ids.
/// TODO: For simplicity, serialize/deserialize is skipped
let solve_fetch_challenges
      (recipient: dyn 1 (fun z -> t_User z))
      (challenges: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
  let (message_ids: Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
    (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) ()
  in
  let message_ids:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Core_models.Slice.Iter.t_Iter
            t_FetchResponse)
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Slice.impl__iter #t_FetchResponse
              (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  challenges
                <:
                t_Slice t_FetchResponse)
            <:
            Core_models.Slice.Iter.t_Iter t_FetchResponse)
        <:
        Core_models.Slice.Iter.t_Iter t_FetchResponse)
      message_ids
      (fun message_ids chall ->
          let message_ids:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            Alloc.Alloc.t_Global =
            message_ids
          in
          let chall:t_FetchResponse = chall in
          let (maybe_kmid_secret: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
            Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
          in
          let maybe_kmid_secret:t_Array u8 (mk_usize 32) =
            Libcrux_hacl_rs.Curve25519_51_.scalarmult maybe_kmid_secret
              (f_get_fetch_sk #(dyn 1 (fun z -> t_User z))
                  #FStar.Tactics.Typeclasses.solve
                  recipient
                <:
                t_Slice u8)
              (chall.f_pmgdh <: t_Slice u8)
          in
          let maybe_message_id:Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            Anyhow.t_Error =
            Securedrop_protocol.Primitives.decrypt_message_id (maybe_kmid_secret <: t_Slice u8)
              (chall.f_enc_id <: t_Slice u8)
          in
          match
            maybe_message_id
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok message_id ->
            let message_ids:Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Alloc.Alloc.t_Global
                message_ids
                message_id
            in
            message_ids
          | _ -> message_ids)
  in
  message_ids

type t_Source = {
  f_keys:t_KeyBundle;
  f_sk_fetch:t_Array u8 (mk_usize 32);
  f_pk_fetch:t_Array u8 (mk_usize 32)
}

/// This doesn't use keys bootstrapped from a passphrase;
/// for now it's the same as journalist setup
let impl_Source__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & t_Source) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Dh_akem.generate_dh_akem_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (sk_dh: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey),
  (pk_dh: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      #Anyhow.t_Error
      out
      "DH keygen (DH-AKEM) failed"
  in
  let (pk_fetch: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let (sk_fetch: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      out
      "DH keygen (Fetching) failed!"
  in
  let (tmp0: t_Array u8 (mk_usize 32)), (out: t_Array u8 (mk_usize 32)) = sk_fetch in
  let sk_fetch:t_Array u8 (mk_usize 32) = tmp0 in
  let pk_fetch:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public pk_fetch out
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey &
        Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Mlkem.generate_mlkem768_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (sk_pqkem_psk: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey),
  (pk_pqkem_psk: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey &
        Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey)
      #Anyhow.t_Error
      out
      "Failed to generate ml-kem keys!"
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Xwing.generate_xwing_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (sk_md: Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey),
  (pk_md: Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
      #Anyhow.t_Error
      out
      "Failed to generate xwing keys"
  in
  let keybundle:t_KeyBundle =
    {
      f_dhakem_sk = Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes sk_dh;
      f_dhakem_pk = Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes pk_dh;
      f_pq_kem_psk_sk
      =
      Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PrivateKey__as_bytes sk_pqkem_psk;
      f_pq_kem_psk_pk
      =
      Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes pk_pqkem_psk;
      f_hybrid_md_sk = Securedrop_protocol.Primitives.Xwing.impl_XWingPrivateKey__as_bytes sk_md;
      f_hybrid_md_pk = Securedrop_protocol.Primitives.Xwing.impl_XWingPublicKey__as_bytes pk_md
    }
    <:
    t_KeyBundle
  in
  let hax_temp_output:t_Source =
    { f_keys = keybundle; f_sk_fetch = sk_fetch; f_pk_fetch = pk_fetch } <: t_Source
  in
  rng, hax_temp_output <: (v_R & t_Source)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_User_for_Source: t_User t_Source =
  {
    f_keybundle_pre = (fun (self: t_Source) (_: Core_models.Option.t_Option usize) -> true);
    f_keybundle_post
    =
    (fun (self: t_Source) (_: Core_models.Option.t_Option usize) (out: t_KeyBundle) -> true);
    f_keybundle = (fun (self: t_Source) (_: Core_models.Option.t_Option usize) -> self.f_keys);
    f_get_fetch_sk_pre = (fun (self: t_Source) -> true);
    f_get_fetch_sk_post = (fun (self: t_Source) (out: t_Array u8 (mk_usize 32)) -> true);
    f_get_fetch_sk = (fun (self: t_Source) -> self.f_sk_fetch);
    f_get_fetch_pk_pre = (fun (self: t_Source) -> true);
    f_get_fetch_pk_post = (fun (self: t_Source) (out: t_Array u8 (mk_usize 32)) -> true);
    f_get_fetch_pk = (fun (self: t_Source) -> self.f_pk_fetch);
    f_get_all_keys_pre = (fun (self: t_Source) -> true);
    f_get_all_keys_post = (fun (self: t_Source) (out: t_Slice t_KeyBundle) -> true);
    f_get_all_keys = fun (self: t_Source) -> Core_models.Slice.Raw.from_ref #t_KeyBundle self.f_keys
  }

type t_Journalist = {
  f_keybundle:Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global;
  f_sk_fetch:t_Array u8 (mk_usize 32);
  f_pk_fetch:t_Array u8 (mk_usize 32);
  f_sk_reply:t_Array u8 (mk_usize 32);
  f_pk_reply:t_Array u8 (mk_usize 32)
}

/// Set up Journalist, creating key_bundle_size short-term key bundles.
let impl_Journalist__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (num_keybundles: usize)
    : (v_R & t_Journalist) =
  let (key_bundle: Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global):Alloc.Vec.t_Vec t_KeyBundle
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #t_KeyBundle num_keybundles
  in
  let (pk_fetch: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let (sk_fetch: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      out
      "DH keygen (Fetching) failed!"
  in
  let (tmp0: t_Array u8 (mk_usize 32)), (out: t_Array u8 (mk_usize 32)) = sk_fetch in
  let sk_fetch:t_Array u8 (mk_usize 32) = tmp0 in
  let pk_fetch:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public pk_fetch out
  in
  let (pk_reply: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let (tmp0: v_R), (out: Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.X25519.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let (sk_reply: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      out
      "DH keygen (Reply) failed!"
  in
  let (tmp0: t_Array u8 (mk_usize 32)), (out: t_Array u8 (mk_usize 32)) = sk_reply in
  let sk_reply:t_Array u8 (mk_usize 32) = tmp0 in
  let pk_reply:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public pk_reply out
  in
  let (key_bundle: Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global), (rng: v_R) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      num_keybundles
      (fun temp_0_ temp_1_ ->
          let (key_bundle: Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          let _:usize = temp_1_ in
          true)
      (key_bundle, rng <: (Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global & v_R))
      (fun temp_0_ temp_1_ ->
          let (key_bundle: Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          let _:usize = temp_1_ in
          let
          (tmp0: v_R),
          (out:
            Core_models.Result.t_Result
              (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error) =
            Securedrop_protocol.Primitives.Dh_akem.generate_dh_akem_keypair #v_R rng
          in
          let rng:v_R = tmp0 in
          let
          (sk_dh: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey),
          (pk_dh: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) =
            Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
              #Anyhow.t_Error
              out
              "DH keygen (DH-AKEM) failed"
          in
          let
          (tmp0: v_R),
          (out:
            Core_models.Result.t_Result
              (Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey &
                Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey) Anyhow.t_Error) =
            Securedrop_protocol.Primitives.Mlkem.generate_mlkem768_keypair #v_R rng
          in
          let rng:v_R = tmp0 in
          let
          (sk_pqkem_psk: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey),
          (pk_pqkem_psk: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey) =
            Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey &
                Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey)
              #Anyhow.t_Error
              out
              "Failed to generate ml-kem keys!"
          in
          let
          (tmp0: v_R),
          (out:
            Core_models.Result.t_Result
              (Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
                Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error) =
            Securedrop_protocol.Primitives.Xwing.generate_xwing_keypair #v_R rng
          in
          let rng:v_R = tmp0 in
          let
          (sk_md: Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey),
          (pk_md: Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) =
            Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
                Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
              #Anyhow.t_Error
              out
              "Failed to generate xwing keys"
          in
          let bundle:t_KeyBundle =
            {
              f_dhakem_sk
              =
              Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes sk_dh;
              f_dhakem_pk
              =
              Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes pk_dh;
              f_pq_kem_psk_sk
              =
              Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PrivateKey__as_bytes sk_pqkem_psk;
              f_pq_kem_psk_pk
              =
              Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes pk_pqkem_psk;
              f_hybrid_md_sk
              =
              Securedrop_protocol.Primitives.Xwing.impl_XWingPrivateKey__as_bytes sk_md;
              f_hybrid_md_pk
              =
              Securedrop_protocol.Primitives.Xwing.impl_XWingPublicKey__as_bytes pk_md
            }
            <:
            t_KeyBundle
          in
          let key_bundle:Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_KeyBundle #Alloc.Alloc.t_Global key_bundle bundle
          in
          key_bundle, rng <: (Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global & v_R))
  in
  let _:Prims.unit =
    match
      Alloc.Vec.impl_1__len #t_KeyBundle #Alloc.Alloc.t_Global key_bundle, num_keybundles
      <:
      (usize & usize)
    with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let hax_temp_output:t_Journalist =
    {
      f_keybundle = key_bundle;
      f_sk_fetch = sk_fetch;
      f_pk_fetch = pk_fetch;
      f_sk_reply = sk_reply;
      f_pk_reply = pk_reply
    }
    <:
    t_Journalist
  in
  rng, hax_temp_output <: (v_R & t_Journalist)

let setup_rng (_: Prims.unit) : Rand_chacha.Chacha.t_ChaCha20Rng =
  let seed:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Getrandom.Error.t_Error) =
    Getrandom.fill seed
  in
  let seed:t_Array u8 (mk_usize 32) = tmp0 in
  let _:Prims.unit =
    Core_models.Result.impl__expect #Prims.unit
      #Getrandom.Error.t_Error
      out
      "getrandom failed- is platform supported?"
  in
  Rand_core.f_from_seed #Rand_chacha.Chacha.t_ChaCha20Rng #FStar.Tactics.Typeclasses.solve seed

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_User_for_Journalist: t_User t_Journalist =
  {
    f_keybundle_pre = (fun (self: t_Journalist) (index: Core_models.Option.t_Option usize) -> true);
    f_keybundle_post
    =
    (fun (self: t_Journalist) (index: Core_models.Option.t_Option usize) (out1: t_KeyBundle) -> true
    );
    f_keybundle
    =
    (fun (self: t_Journalist) (index: Core_models.Option.t_Option usize) ->
        match index <: Core_models.Option.t_Option usize with
        | Core_models.Option.Option_Some i ->
          Core_models.Option.impl__unwrap_or_else #t_KeyBundle
            (Core_models.Slice.impl__get #t_KeyBundle
                #usize
                (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global)
                    #FStar.Tactics.Typeclasses.solve
                    self.f_keybundle
                  <:
                  t_Slice t_KeyBundle)
                i
              <:
              Core_models.Option.t_Option t_KeyBundle)
            (fun temp_0_ ->
                let _:Prims.unit = temp_0_ in
                let args:usize = i <: usize in
                let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                  let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list
                in
                Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic_fmt (Core_models.Fmt.Rt.impl_1__new_v1
                          (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["Bad index: "] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Rust_primitives.Hax.t_Never))
        | Core_models.Option.Option_None  ->
          let rng:Rand_chacha.Chacha.t_ChaCha20Rng = setup_rng () in
          let (tmp0: Rand_chacha.Chacha.t_ChaCha20Rng), (out: u32) =
            Rand_core.f_next_u32 #Rand_chacha.Chacha.t_ChaCha20Rng
              #FStar.Tactics.Typeclasses.solve
              rng
          in
          let rng:Rand_chacha.Chacha.t_ChaCha20Rng = tmp0 in
          let choice:usize =
            (cast (out <: u32) <: usize) %!
            (Alloc.Vec.impl_1__len #t_KeyBundle #Alloc.Alloc.t_Global self.f_keybundle <: usize)
          in
          Core_models.Option.impl__expect #t_KeyBundle
            (Core_models.Slice.impl__get #t_KeyBundle
                #usize
                (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global)
                    #FStar.Tactics.Typeclasses.solve
                    self.f_keybundle
                  <:
                  t_Slice t_KeyBundle)
                choice
              <:
              Core_models.Option.t_Option t_KeyBundle)
            "Need at least one keybundle");
    f_get_all_keys_pre = (fun (self: t_Journalist) -> true);
    f_get_all_keys_post = (fun (self: t_Journalist) (out: t_Slice t_KeyBundle) -> true);
    f_get_all_keys
    =
    (fun (self: t_Journalist) ->
        Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec t_KeyBundle Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          self.f_keybundle);
    f_get_fetch_sk_pre = (fun (self: t_Journalist) -> true);
    f_get_fetch_sk_post = (fun (self: t_Journalist) (out: t_Array u8 (mk_usize 32)) -> true);
    f_get_fetch_sk = (fun (self: t_Journalist) -> self.f_sk_fetch);
    f_get_fetch_pk_pre = (fun (self: t_Journalist) -> true);
    f_get_fetch_pk_post = (fun (self: t_Journalist) (out: t_Array u8 (mk_usize 32)) -> true);
    f_get_fetch_pk = fun (self: t_Journalist) -> self.f_pk_fetch
  }

let setup_rng_deterministic (seed: t_Array u8 (mk_usize 32)) : Rand_chacha.Chacha.t_ChaCha20Rng =
  Rand_core.f_from_seed #Rand_chacha.Chacha.t_ChaCha20Rng #FStar.Tactics.Typeclasses.solve seed

let bench_encrypt
      (seed32: t_Array u8 (mk_usize 32))
      (sender recipient: dyn 1 (fun z -> t_User z))
      (recipient_bundle_index: usize)
      (plaintext: t_Slice u8)
    : t_Envelope =
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng =
    Rand_core.f_from_seed #Rand_chacha.Chacha.t_ChaCha20Rng #FStar.Tactics.Typeclasses.solve seed32
  in
  let (tmp0: Rand_chacha.Chacha.t_ChaCha20Rng), (out: t_Envelope) =
    encrypt #Rand_chacha.Chacha.t_ChaCha20Rng
      rng
      (Rust_primitives.unsize sender <: dyn 1 (fun z -> t_User z))
      plaintext
      (Rust_primitives.unsize recipient <: dyn 1 (fun z -> t_User z))
      (Core_models.Option.Option_Some recipient_bundle_index <: Core_models.Option.t_Option usize)
  in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = tmp0 in
  out

let bench_decrypt (recipient: dyn 1 (fun z -> t_User z)) (envelope: t_Envelope) : t_Plaintext =
  decrypt (Rust_primitives.unsize recipient <: dyn 1 (fun z -> t_User z)) envelope

let bench_fetch
      (recipient: dyn 1 (fun z -> t_User z))
      (challenges: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)
    : Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
  solve_fetch_challenges (Rust_primitives.unsize recipient <: dyn 1 (fun z -> t_User z)) challenges
