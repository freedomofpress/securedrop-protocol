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
val impl_2': Core_models.Fmt.t_Debug t_Plaintext

unfold
let impl_2 = impl_2'

let impl_3: Core_models.Clone.t_Clone t_Plaintext =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_Plaintext__KEY_HEADER_LEN: usize =
  Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN +!
  Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__LEN

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
  impl_Plaintext__KEY_HEADER_LEN +!
  (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_msg <: usize)

let impl_Plaintext__from_bytes (pt_bytes: t_Slice u8)
    : Core_models.Result.t_Result t_Plaintext Anyhow.t_Error =
  if (Core_models.Slice.impl__len #u8 pt_bytes <: usize) <. impl_Plaintext__KEY_HEADER_LEN
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
          Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__from_bytes (pt_bytes.[
                {
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
          Core_models.Result.t_Result
            Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey Anyhow.t_Error
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
          Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result t_Plaintext Anyhow.t_Error)
    | Core_models.Result.Result_Err err ->
      Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_Plaintext Anyhow.t_Error

/// Padded plaintext structure to retrieve encryptable bytes for a Plaintext.
type t_PaddedPlaintext = | PaddedPlaintext : t_Plaintext -> t_PaddedPlaintext

/// Length of a padded plaintext message.
/// TODO(#229): Choose a size based on real requirements
let impl_PaddedPlaintext__LEN: usize = mk_usize 100000

let impl_PaddedPlaintext__PREFIX_LEN: usize = mk_usize 4

let impl_PaddedPlaintext__MAX_CONTENT_LEN: usize =
  impl_PaddedPlaintext__LEN -! impl_PaddedPlaintext__PREFIX_LEN

/// Returns an error if the value is too large to fit in the padded length.
let impl_PaddedPlaintext__new (plaintext: t_Plaintext)
    : Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error =
  if (impl_Plaintext__len plaintext <: usize) >. impl_PaddedPlaintext__MAX_CONTENT_LEN
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["Plaintext too long for padding"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    Core_models.Result.Result_Err (Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error
  else
    Core_models.Result.Result_Ok (PaddedPlaintext plaintext <: t_PaddedPlaintext)
    <:
    Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error

/// Returns a padded plaintext [u32_le(len) || value || 00...]
let impl_PaddedPlaintext__to_bytes (self: t_PaddedPlaintext)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let content:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = impl_Plaintext__to_bytes self._0 in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match
          Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global content, impl_Plaintext__len self._0
          <:
          (usize & usize)
        with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8 impl_PaddedPlaintext__LEN
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Core_models.Num.impl_u32__to_le_bytes (cast (Alloc.Vec.impl_1__len #u8
                  #Alloc.Alloc.t_Global
                  content
                <:
                usize)
            <:
            u32)
        <:
        t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Alloc.Vec.impl_1__as_slice content <: t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__resize #u8 #Alloc.Alloc.t_Global out impl_PaddedPlaintext__LEN (mk_u8 0)
  in
  out

/// Create a PaddedPlaintext from bytes. Returns an error if the length is not equal to the expected padded length.
let impl_PaddedPlaintext__from_bytes (bytes: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    : Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error =
  if (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global bytes <: usize) <>. impl_PaddedPlaintext__LEN
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["Invalid padded length"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    Core_models.Result.Result_Err (Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error
  else
    let (len_bytes: t_Array u8 (mk_usize 4)):t_Array u8 (mk_usize 4) =
      Core_models.Result.impl__unwrap #(t_Array u8 (mk_usize 4))
        #Core_models.Array.t_TryFromSliceError
        (Core_models.Convert.f_try_into #(t_Slice u8)
            #(t_Array u8 (mk_usize 4))
            #FStar.Tactics.Typeclasses.solve
            (bytes.[ {
                  Core_models.Ops.Range.f_start = mk_usize 0;
                  Core_models.Ops.Range.f_end = mk_usize 4
                }
                <:
                Core_models.Ops.Range.t_Range usize ]
              <:
              t_Slice u8)
          <:
          Core_models.Result.t_Result (t_Array u8 (mk_usize 4))
            Core_models.Array.t_TryFromSliceError)
    in
    let len:usize = cast (Core_models.Num.impl_u32__from_le_bytes len_bytes <: u32) <: usize in
    if len >. impl_PaddedPlaintext__MAX_CONTENT_LEN
    then
      let error:Anyhow.t_Error =
        Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
              (let list = ["Content too large to unpad"] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
            <:
            Core_models.Fmt.t_Arguments)
      in
      Core_models.Result.Result_Err (Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error
    else
      match
        Rust_primitives.Hax.Folds.fold_return (Core_models.Iter.Traits.Collect.f_into_iter #(t_Slice
                u8)
              #FStar.Tactics.Typeclasses.solve
              (bytes.[ { Core_models.Ops.Range.f_start = mk_usize 4 +! len <: usize }
                  <:
                  Core_models.Ops.Range.t_RangeFrom usize ]
                <:
                t_Slice u8)
            <:
            Core_models.Slice.Iter.t_Iter u8)
          ()
          (fun temp_0_ byte ->
              let _:Prims.unit = temp_0_ in
              let byte:u8 = byte in
              if byte <>. mk_u8 0 <: bool
              then
                let error:Anyhow.t_Error =
                  Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                        (let list = ["Invalid zero padding"] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                      <:
                      Core_models.Fmt.t_Arguments)
                in
                Core_models.Ops.Control_flow.ControlFlow_Break
                (Core_models.Ops.Control_flow.ControlFlow_Break
                  (Core_models.Result.Result_Err (Anyhow.__private.must_use error)
                    <:
                    Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error)
                  <:
                  Core_models.Ops.Control_flow.t_ControlFlow
                    (Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error)
                    (Prims.unit & Prims.unit))
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error)
                      (Prims.unit & Prims.unit)) Prims.unit
              else
                Core_models.Ops.Control_flow.ControlFlow_Continue ()
                <:
                Core_models.Ops.Control_flow.t_ControlFlow
                  (Core_models.Ops.Control_flow.t_ControlFlow
                      (Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error)
                      (Prims.unit & Prims.unit)) Prims.unit)
        <:
        Core_models.Ops.Control_flow.t_ControlFlow
          (Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error) Prims.unit
      with
      | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core_models.Ops.Control_flow.ControlFlow_Continue _ ->
        match
          impl_Plaintext__from_bytes (bytes.[ {
                  Core_models.Ops.Range.f_start = mk_usize 4;
                  Core_models.Ops.Range.f_end = mk_usize 4 +! len <: usize
                }
                <:
                Core_models.Ops.Range.t_Range usize ]
              <:
              t_Slice u8)
          <:
          Core_models.Result.t_Result t_Plaintext Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok plaintext -> impl_PaddedPlaintext__new plaintext
        | Core_models.Result.Result_Err err ->
          Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result t_PaddedPlaintext Anyhow.t_Error

let impl_PaddedPlaintext__into_inner (self: t_PaddedPlaintext) : t_Plaintext = self._0
