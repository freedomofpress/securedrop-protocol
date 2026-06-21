module Securedrop_protocol_minimal.Wire_format
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Ciphertext in
  ()

let v_LEN_REPLY_PUBKEY: usize = mk_usize 1216

let v_LEN_FETCH_KEY: usize = mk_usize 32

let v_PREFIX_LEN: usize = v_LEN_REPLY_PUBKEY +! v_LEN_FETCH_KEY

let v_TAG_V0: u8 = mk_u8 0

let v_TAG_V1: u8 = mk_u8 1

type t_WireError =
  | WireError_UnknownVersion : t_WireError
  | WireError_TooShort : t_WireError
  | WireError_RoundTripFailed : t_WireError
  | WireError_NonCanonical : t_WireError

let t_WireError_cast_to_repr (x: t_WireError) : isize =
  match x <: t_WireError with
  | WireError_UnknownVersion  -> mk_isize 0
  | WireError_TooShort  -> mk_isize 1
  | WireError_RoundTripFailed  -> mk_isize 2
  | WireError_NonCanonical  -> mk_isize 3

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl': Core_models.Fmt.t_Debug t_WireError

unfold
let impl = impl'

let impl_1: Core_models.Clone.t_Clone t_WireError =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Marker.t_StructuralPartialEq t_WireError

unfold
let impl_2 = impl_2'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Cmp.t_PartialEq t_WireError t_WireError

unfold
let impl_3 = impl_3'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Cmp.t_Eq t_WireError

unfold
let impl_4 = impl_4'

let version_tag (bytes: t_Slice u8) : Core_models.Option.t_Option u8 =
  if Core_models.Slice.impl__is_empty #u8 bytes
  then Core_models.Option.Option_None <: Core_models.Option.t_Option u8
  else Core_models.Option.Option_Some bytes.[ mk_usize 0 ] <: Core_models.Option.t_Option u8

let v_MAX_MSG_LEN: usize = (Core_models.Num.impl_usize__MAX -! v_PREFIX_LEN <: usize) -! mk_usize 1

let serialize_v0 (p: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (requires
        (Alloc.Vec.impl_1__len #u8
            #Alloc.Alloc.t_Global
            p.Securedrop_protocol_minimal.Ciphertext.f_msg
          <:
          usize) <=.
        v_MAX_MSG_LEN)
      (fun _ -> Prims.l_True) =
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global buf v_TAG_V0
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (p.Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (p.Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Alloc.Vec.impl_1__as_slice p.Securedrop_protocol_minimal.Ciphertext.f_msg <: t_Slice u8)
  in
  buf

let deserialize_v0_body (body: t_Slice u8)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError =
  if (Core_models.Slice.impl__len #u8 body <: usize) <. v_PREFIX_LEN
  then
    Core_models.Result.Result_Err (WireError_TooShort <: t_WireError)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError
  else
    let sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216) =
      Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1216)
    in
    let sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216) =
      Core_models.Slice.impl__copy_from_slice #u8
        sender_reply_pubkey_hybrid
        (body.[ {
              Core_models.Ops.Range.f_start = mk_usize 0;
              Core_models.Ops.Range.f_end = v_LEN_REPLY_PUBKEY
            }
            <:
            Core_models.Ops.Range.t_Range usize ]
          <:
          t_Slice u8)
    in
    let sender_fetch_key:t_Array u8 (mk_usize 32) =
      Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
    in
    let sender_fetch_key:t_Array u8 (mk_usize 32) =
      Core_models.Slice.impl__copy_from_slice #u8
        sender_fetch_key
        (body.[ {
              Core_models.Ops.Range.f_start = v_LEN_REPLY_PUBKEY;
              Core_models.Ops.Range.f_end = v_PREFIX_LEN
            }
            <:
            Core_models.Ops.Range.t_Range usize ]
          <:
          t_Slice u8)
    in
    let msg:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Slice.impl__to_vec #u8
        (body.[ { Core_models.Ops.Range.f_start = v_PREFIX_LEN }
            <:
            Core_models.Ops.Range.t_RangeFrom usize ]
          <:
          t_Slice u8)
    in
    Core_models.Result.Result_Ok
    ({
        Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid
        =
        sender_reply_pubkey_hybrid;
        Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key = sender_fetch_key;
        Securedrop_protocol_minimal.Ciphertext.f_msg = msg
      }
      <:
      Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError

let serialize_v1 (p: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (requires
        (Alloc.Vec.impl_1__len #u8
            #Alloc.Alloc.t_Global
            p.Securedrop_protocol_minimal.Ciphertext.f_msg
          <:
          usize) <=.
        v_MAX_MSG_LEN)
      (fun _ -> Prims.l_True) =
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global buf v_TAG_V1
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (p.Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (p.Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid <: t_Slice u8)
  in
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      buf
      (Alloc.Vec.impl_1__as_slice p.Securedrop_protocol_minimal.Ciphertext.f_msg <: t_Slice u8)
  in
  buf

let deserialize_v1_body (body: t_Slice u8)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError =
  if (Core_models.Slice.impl__len #u8 body <: usize) <. v_PREFIX_LEN
  then
    Core_models.Result.Result_Err (WireError_TooShort <: t_WireError)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError
  else
    let sender_fetch_key:t_Array u8 (mk_usize 32) =
      Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
    in
    let sender_fetch_key:t_Array u8 (mk_usize 32) =
      Core_models.Slice.impl__copy_from_slice #u8
        sender_fetch_key
        (body.[ {
              Core_models.Ops.Range.f_start = mk_usize 0;
              Core_models.Ops.Range.f_end = v_LEN_FETCH_KEY
            }
            <:
            Core_models.Ops.Range.t_Range usize ]
          <:
          t_Slice u8)
    in
    let sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216) =
      Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1216)
    in
    let sender_reply_pubkey_hybrid:t_Array u8 (mk_usize 1216) =
      Core_models.Slice.impl__copy_from_slice #u8
        sender_reply_pubkey_hybrid
        (body.[ {
              Core_models.Ops.Range.f_start = v_LEN_FETCH_KEY;
              Core_models.Ops.Range.f_end = v_PREFIX_LEN
            }
            <:
            Core_models.Ops.Range.t_Range usize ]
          <:
          t_Slice u8)
    in
    let msg:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Slice.impl__to_vec #u8
        (body.[ { Core_models.Ops.Range.f_start = v_PREFIX_LEN }
            <:
            Core_models.Ops.Range.t_RangeFrom usize ]
          <:
          t_Slice u8)
    in
    Core_models.Result.Result_Ok
    ({
        Securedrop_protocol_minimal.Ciphertext.f_sender_reply_pubkey_hybrid
        =
        sender_reply_pubkey_hybrid;
        Securedrop_protocol_minimal.Ciphertext.f_sender_fetch_key = sender_fetch_key;
        Securedrop_protocol_minimal.Ciphertext.f_msg = msg
      }
      <:
      Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError

let deserialize (bytes: t_Slice u8)
    : Prims.Pure
      (Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext
            t_WireError =
            result
          in
          match
            result
            <:
            Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext
              t_WireError
          with
          | Core_models.Result.Result_Ok p ->
            (Alloc.Vec.impl_1__len #u8
                #Alloc.Alloc.t_Global
                p.Securedrop_protocol_minimal.Ciphertext.f_msg
              <:
              usize) <=.
            v_MAX_MSG_LEN &&
            (Alloc.Vec.impl_1__as_slice #u8
                #Alloc.Alloc.t_Global
                (serialize_v0 p <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              <:
              t_Slice u8) =.
            bytes
          | Core_models.Result.Result_Err _ -> true) =
  match version_tag bytes <: Core_models.Option.t_Option u8 with
  | Core_models.Option.Option_Some (Rust_primitives.Integers.MkInt 0) ->
    (match
        deserialize_v0_body (bytes.[ { Core_models.Ops.Range.f_start = mk_usize 1 }
              <:
              Core_models.Ops.Range.t_RangeFrom usize ]
            <:
            t_Slice u8)
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError
      with
      | Core_models.Result.Result_Ok ok ->
        let p:Securedrop_protocol_minimal.Ciphertext.t_Plaintext = ok in
        if
          (Alloc.Vec.impl_1__len #u8
              #Alloc.Alloc.t_Global
              p.Securedrop_protocol_minimal.Ciphertext.f_msg
            <:
            usize) <=.
          v_MAX_MSG_LEN &&
          (Alloc.Vec.impl_1__as_slice #u8
              #Alloc.Alloc.t_Global
              (serialize_v0 p <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            <:
            t_Slice u8) =.
          bytes
        then
          Core_models.Result.Result_Ok p
          <:
          Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError
        else
          Core_models.Result.Result_Err (WireError_NonCanonical <: t_WireError)
          <:
          Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError)
  | _ ->
    Core_models.Result.Result_Err (WireError_UnknownVersion <: t_WireError)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError

let serialize (p: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    : Prims.Pure (Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_WireError)
      (requires
        (Alloc.Vec.impl_1__len #u8
            #Alloc.Alloc.t_Global
            p.Securedrop_protocol_minimal.Ciphertext.f_msg
          <:
          usize) <=.
        v_MAX_MSG_LEN)
      (ensures
        fun result ->
          let result:Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            t_WireError =
            result
          in
          match
            result
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_WireError
          with
          | Core_models.Result.Result_Ok buf ->
            (deserialize (Alloc.Vec.impl_1__as_slice buf <: t_Slice u8)
              <:
              Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext
                t_WireError) =.
            (Core_models.Result.Result_Ok
              (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Ciphertext.t_Plaintext
                  #FStar.Tactics.Typeclasses.solve
                  p
                <:
                Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
              <:
              Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext
                t_WireError)
          | Core_models.Result.Result_Err _ -> true) =
  let buf:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = serialize_v0 p in
  if
    (deserialize (Alloc.Vec.impl_1__as_slice buf <: t_Slice u8)
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError) =.
    (Core_models.Result.Result_Ok
      (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Ciphertext.t_Plaintext
          #FStar.Tactics.Typeclasses.solve
          p
        <:
        Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError)
  then
    Core_models.Result.Result_Ok buf
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_WireError
  else
    Core_models.Result.Result_Err (WireError_RoundTripFailed <: t_WireError)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_WireError

let deserialize_versioned (bytes: t_Slice u8)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError =
  match version_tag bytes <: Core_models.Option.t_Option u8 with
  | Core_models.Option.Option_Some (Rust_primitives.Integers.MkInt 0) ->
    deserialize_v0_body (bytes.[ { Core_models.Ops.Range.f_start = mk_usize 1 }
          <:
          Core_models.Ops.Range.t_RangeFrom usize ]
        <:
        t_Slice u8)
  | Core_models.Option.Option_Some (Rust_primitives.Integers.MkInt 1) ->
    deserialize_v1_body (bytes.[ { Core_models.Ops.Range.f_start = mk_usize 1 }
          <:
          Core_models.Ops.Range.t_RangeFrom usize ]
        <:
        t_Slice u8)
  | _ ->
    Core_models.Result.Result_Err (WireError_UnknownVersion <: t_WireError)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Ciphertext.t_Plaintext t_WireError

let lemma_version_tag_v0 (p: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    : Lemma
    (ensures
      (Alloc.Vec.impl_1__len #u8
          #Alloc.Alloc.t_Global
          p.Securedrop_protocol_minimal.Ciphertext.f_msg
        <:
        usize) >.
      v_MAX_MSG_LEN ||
      (version_tag (Alloc.Vec.impl_1__as_slice (serialize_v0 p
                <:
                Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            <:
            t_Slice u8)
        <:
        Core_models.Option.t_Option u8) =.
      (Core_models.Option.Option_Some v_TAG_V0 <: Core_models.Option.t_Option u8)) = ()

let lemma_version_tag_v1 (p: Securedrop_protocol_minimal.Ciphertext.t_Plaintext)
    : Lemma
    (ensures
      (Alloc.Vec.impl_1__len #u8
          #Alloc.Alloc.t_Global
          p.Securedrop_protocol_minimal.Ciphertext.f_msg
        <:
        usize) >.
      v_MAX_MSG_LEN ||
      (version_tag (Alloc.Vec.impl_1__as_slice (serialize_v1 p
                <:
                Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            <:
            t_Slice u8)
        <:
        Core_models.Option.t_Option u8) =.
      (Core_models.Option.Option_Some v_TAG_V1 <: Core_models.Option.t_Option u8)) = ()
