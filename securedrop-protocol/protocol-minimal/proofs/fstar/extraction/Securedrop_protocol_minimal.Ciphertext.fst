module Securedrop_protocol_minimal.Ciphertext
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// The full submission `(C_S, X, Z)` sent from sender to server in step 6.
/// - `C_S = (ct^APKE, ct^PKE)`: the two ciphertexts
/// - `X = g^x`: ephemeral DH public key (hint)
/// - `Z = (pk_R^fetch)^x`: DH share for fetching (hint)
/// The server stores `(id, C_S, X, Z)` per message.
type t_Envelope = {
  f_ct_apke:Securedrop_protocol_minimal.Message.t_MessageCiphertext;
  f_ct_pke:Securedrop_protocol_minimal.Metadata.t_MetadataCiphertext;
  f_mgdh_pubkey:t_Array u8 (mk_usize 32);
  f_mgdh:t_Array u8 (mk_usize 32)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Fmt.t_Debug t_Envelope

unfold
let impl_3 = impl_3'

let impl_4: Core_models.Clone.t_Clone t_Envelope =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_Envelope__size_hint (self: t_Envelope) : usize =
  (Securedrop_protocol_minimal.Message.impl_MessageCiphertext__len self.f_ct_apke <: usize) +!
  (Securedrop_protocol_minimal.Metadata.impl_MetadataCiphertext__len self.f_ct_pke <: usize)

let impl_Envelope__cmessage_len (self: t_Envelope) : usize =
  Securedrop_protocol_minimal.Message.impl_MessageCiphertext__len self.f_ct_apke

let impl_Envelope__cmetadata_len (self: t_Envelope) : usize =
  Securedrop_protocol_minimal.Metadata.impl_MetadataCiphertext__len self.f_ct_pke

/// Toy pt structure - TODO: provide params in correct order
type t_Plaintext = {
  f_sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216);
  f_sender_fetch_key:t_Array u8 (mk_usize 32);
  f_msg:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_Plaintext

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_Plaintext =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_Plaintext__to_bytes (self: t_Plaintext) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (self.f_sender_reply_pubkey_hybrid <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (self.f_sender_fetch_key <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          self.f_msg
        <:
        t_Slice u8)
  in
  buf

let impl_Plaintext__len (self: t_Plaintext) : usize =
  (Securedrop_protocol_minimal.Constants.v_LEN_XWING_ENCAPS_KEY +!
    Securedrop_protocol_minimal.Constants.v_LEN_DH_ITEM
    <:
    usize) +!
  (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_msg <: usize)

let impl_Plaintext__from_bytes (pt_bytes: t_Slice u8)
    : Core_models.Result.t_Result t_Plaintext Anyhow.t_Error =
  let offset:usize = mk_usize 0 in
  let sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1216)
  in
  let sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216) =
    Core_models.Slice.impl__copy_from_slice #u8
      sender_reply_pubkey_hybrid
      (pt_bytes.[ {
            Core_models.Ops.Range.f_start = offset;
            Core_models.Ops.Range.f_end
            =
            offset +! Securedrop_protocol_minimal.Constants.v_LEN_XWING_ENCAPS_KEY <: usize
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let offset:usize = offset +! Securedrop_protocol_minimal.Constants.v_LEN_XWING_ENCAPS_KEY in
  let sender_fetch_key:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let sender_fetch_key:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      sender_fetch_key
      (pt_bytes.[ {
            Core_models.Ops.Range.f_start = offset;
            Core_models.Ops.Range.f_end
            =
            offset +! Securedrop_protocol_minimal.Constants.v_LEN_DH_ITEM <: usize
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let offset:usize = offset +! Securedrop_protocol_minimal.Constants.v_LEN_DH_ITEM in
  let msg:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec #u8
      (pt_bytes.[ { Core_models.Ops.Range.f_start = offset }
          <:
          Core_models.Ops.Range.t_RangeFrom usize ]
        <:
        t_Slice u8)
  in
  Core_models.Result.Result_Ok
  ({
      f_sender_reply_pubkey_hybrid = sender_reply_pubkey_hybrid;
      f_sender_fetch_key = sender_fetch_key;
      f_msg = msg
    }
    <:
    t_Plaintext)
  <:
  Core_models.Result.t_Result t_Plaintext Anyhow.t_Error

type t_FetchResponse = {
  f_enc_id:t_Array u8 (mk_usize 44);
  f_pmgdh:t_Array u8 (mk_usize 32)
}

let impl_7: Core_models.Clone.t_Clone t_FetchResponse =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_8': Core_models.Fmt.t_Debug t_FetchResponse

unfold
let impl_8 = impl_8'

let impl_FetchResponse__new (enc_id: t_Array u8 (mk_usize 44)) (pmgdh: t_Array u8 (mk_usize 32))
    : t_FetchResponse = { f_enc_id = enc_id; f_pmgdh = pmgdh } <: t_FetchResponse
