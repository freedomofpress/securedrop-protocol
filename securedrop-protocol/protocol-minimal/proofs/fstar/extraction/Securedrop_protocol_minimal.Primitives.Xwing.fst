module Securedrop_protocol_minimal.Primitives.Xwing
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let v_XWING_PUBLIC_KEY_LEN: usize = mk_usize 1216

let v_XWING_PRIVATE_KEY_LEN: usize = mk_usize 32

/// XWING public key.
type t_XWingPublicKey = | XWingPublicKey : t_Array u8 (mk_usize 1216) -> t_XWingPublicKey

/// XWING private key.
type t_XWingPrivateKey = | XWingPrivateKey : t_Array u8 (mk_usize 32) -> t_XWingPrivateKey

/// Create from bytes
let impl_XWingPublicKey__from_bytes (bytes: t_Array u8 (mk_usize 1216)) : t_XWingPublicKey =
  XWingPublicKey bytes <: t_XWingPublicKey

/// Create from bytes
let impl_XWingPrivateKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_XWingPrivateKey =
  XWingPrivateKey bytes <: t_XWingPrivateKey

/// Helper, convert libcrux type to our key types
let typed (sk: Libcrux_kem.t_PrivateKey) (pk: Libcrux_kem.t_PublicKey)
    : Prims.Pure (Core_models.Result.t_Result (t_XWingPrivateKey & t_XWingPublicKey) Anyhow.t_Error)
      Prims.l_True
      (ensures
        fun result ->
          let result:Core_models.Result.t_Result (t_XWingPrivateKey & t_XWingPublicKey)
            Anyhow.t_Error =
            result
          in
          Core_models.Result.impl__is_ok #(t_XWingPrivateKey & t_XWingPublicKey)
            #Anyhow.t_Error
            result) =
  let private_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Libcrux_kem.impl_PrivateKey__encode sk
  in
  let public_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Libcrux_kem.impl_PublicKey__encode pk
  in
  if
    (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global private_key_bytes <: usize) <>.
    v_XWING_PRIVATE_KEY_LEN ||
    (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global public_key_bytes <: usize) <>.
    v_XWING_PUBLIC_KEY_LEN
  then
    let _:Prims.unit = Hax_lib.v_assert false in
    let args:(usize & usize) =
      Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global private_key_bytes,
      Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global public_key_bytes
      <:
      (usize & usize)
    in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 2) =
      let list =
        [
          Core_models.Fmt.Rt.impl__new_display #usize args._1;
          Core_models.Fmt.Rt.impl__new_display #usize args._2
        ]
      in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
      Rust_primitives.Hax.array_of_list 2 list
    in
    Core_models.Result.Result_Err
    (Anyhow.Error.impl__msg #Alloc.String.t_String
        (Core_models.Hint.must_use #Alloc.String.t_String
            (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                    (mk_usize 2)
                    (let list = ["Unexpected XWING key sizes: private="; ", public="] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    args
                  <:
                  Core_models.Fmt.t_Arguments)
              <:
              Alloc.String.t_String)
          <:
          Alloc.String.t_String))
    <:
    Core_models.Result.t_Result (t_XWingPrivateKey & t_XWingPublicKey) Anyhow.t_Error
  else
    match
      Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
        #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #Anyhow.t_Error
        (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #(t_Array u8 (mk_usize 32))
            #FStar.Tactics.Typeclasses.solve
            private_key_bytes
          <:
          Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
            (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
        (fun temp_0_ ->
            let _:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = temp_0_ in
            let error:Anyhow.t_Error =
              Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                    (let list = ["Failed to convert private key bytes"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core_models.Fmt.t_Arguments)
            in
            Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
    with
    | Core_models.Result.Result_Ok hoist2 ->
      let private_key:t_XWingPrivateKey = impl_XWingPrivateKey__from_bytes hoist2 in
      (match
          Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 1216))
            #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #Anyhow.t_Error
            (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #(t_Array u8 (mk_usize 1216))
                #FStar.Tactics.Typeclasses.solve
                public_key_bytes
              <:
              Core_models.Result.t_Result (t_Array u8 (mk_usize 1216))
                (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            (fun temp_0_ ->
                let _:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = temp_0_ in
                let error:Anyhow.t_Error =
                  Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                        (let list = ["Failed to convert public key bytes"] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                      <:
                      Core_models.Fmt.t_Arguments)
                in
                Anyhow.__private.must_use error)
          <:
          Core_models.Result.t_Result (t_Array u8 (mk_usize 1216)) Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok hoist3 ->
          let public_key:t_XWingPublicKey = impl_XWingPublicKey__from_bytes hoist3 in
          Core_models.Result.Result_Ok
          (private_key, public_key <: (t_XWingPrivateKey & t_XWingPublicKey))
          <:
          Core_models.Result.t_Result (t_XWingPrivateKey & t_XWingPublicKey) Anyhow.t_Error
        | Core_models.Result.Result_Err err ->
          Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result (t_XWingPrivateKey & t_XWingPublicKey) Anyhow.t_Error)
    | Core_models.Result.Result_Err err ->
      Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (t_XWingPrivateKey & t_XWingPublicKey) Anyhow.t_Error
