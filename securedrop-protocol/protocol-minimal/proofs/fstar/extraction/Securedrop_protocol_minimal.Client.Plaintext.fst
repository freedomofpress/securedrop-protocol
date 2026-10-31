module Securedrop_protocol_minimal.Client.Plaintext
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Toy pt structure
type t_Plaintext = {
  f_sender_fetch_key:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey;
  f_sender_reply_pubkey_hybrid:Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey;
  f_msg:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Fmt.t_Debug t_Plaintext

unfold
let impl_1 = impl_1'

let impl_2: Core_models.Clone.t_Clone t_Plaintext =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_Plaintext__to_bytes (self: t_Plaintext) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__into_bytes self
            .f_sender_fetch_key
        <:
        t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__as_bytes self
            .f_sender_reply_pubkey_hybrid
        <:
        t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Alloc.Vec.impl_1__as_slice self.f_msg <: t_Slice u8)
  in
  buf

let impl_Plaintext__len (self: t_Plaintext) : usize =
  (Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN +!
    Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__LEN
    <:
    usize) +!
  (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_msg <: usize)

let impl_Plaintext__from_bytes (pt_bytes: t_Slice u8)
    : Core_models.Result.t_Result t_Plaintext Anyhow.t_Error =
  if
    (Core_models.Slice.impl__len #u8 pt_bytes <: usize) <.
    (Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN +!
      Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__LEN
      <:
      usize)
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["plaintext is shorter than its key header"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    Core_models.Result.Result_Err (Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result t_Plaintext Anyhow.t_Error
  else
    let offset:usize = mk_usize 0 in
    let fetch_key_bytes:t_Array u8 (mk_usize 32) =
      Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
    in
    let fetch_key_bytes:t_Array u8 (mk_usize 32) =
      Core_models.Slice.impl__copy_from_slice #u8
        fetch_key_bytes
        (pt_bytes.[ {
              Core_models.Ops.Range.f_start = offset;
              Core_models.Ops.Range.f_end
              =
              offset +! Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN
              <:
              usize
            }
            <:
            Core_models.Ops.Range.t_Range usize ]
          <:
          t_Slice u8)
    in
    match
      Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__decode fetch_key_bytes
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
        Anyhow.t_Error
    with
    | Core_models.Result.Result_Ok sender_fetch_key ->
      let offset:usize =
        offset +! Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN
      in
      (match
          Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__from_bytes (pt_bytes.[ {
                  Core_models.Ops.Range.f_start = offset;
                  Core_models.Ops.Range.f_end
                  =
                  offset +! Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__LEN
                  <:
                  usize
                }
                <:
                Core_models.Ops.Range.t_Range usize ]
              <:
              t_Slice u8)
          <:
          Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey
            Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok sender_reply_pubkey_hybrid ->
          let offset:usize =
            offset +! Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__LEN
          in
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
              f_sender_fetch_key = sender_fetch_key;
              f_sender_reply_pubkey_hybrid = sender_reply_pubkey_hybrid;
              f_msg = msg
            }
            <:
            t_Plaintext)
          <:
          Core_models.Result.t_Result t_Plaintext Anyhow.t_Error
        | Core_models.Result.Result_Err err ->
          Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_Plaintext Anyhow.t_Error)
    | Core_models.Result.Result_Err err ->
      Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_Plaintext Anyhow.t_Error
