module Securedrop_protocol.Primitives.Mlkem
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_kem in
  let open Rand_core in
  ()

let v_MLKEM768_PUBLIC_KEY_LEN: usize = mk_usize 1184

let v_MLKEM768_PRIVATE_KEY_LEN: usize = mk_usize 2400

/// MLKEM-768 public key.
type t_MLKEM768PublicKey = | MLKEM768PublicKey : t_Array u8 (mk_usize 1184) -> t_MLKEM768PublicKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Fmt.t_Debug t_MLKEM768PublicKey

unfold
let impl_2 = impl_2'

let impl_3: Core_models.Clone.t_Clone t_MLKEM768PublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// MLKEM-768 private key.
type t_MLKEM768PrivateKey =
  | MLKEM768PrivateKey : t_Array u8 (mk_usize 2400) -> t_MLKEM768PrivateKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Fmt.t_Debug t_MLKEM768PrivateKey

unfold
let impl_4 = impl_4'

let impl_5: Core_models.Clone.t_Clone t_MLKEM768PrivateKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Get the public key as bytes
let impl_MLKEM768PublicKey__as_bytes (self: t_MLKEM768PublicKey) : t_Array u8 (mk_usize 1184) =
  self._0

/// Create from bytes
let impl_MLKEM768PublicKey__from_bytes (bytes: t_Array u8 (mk_usize 1184)) : t_MLKEM768PublicKey =
  MLKEM768PublicKey bytes <: t_MLKEM768PublicKey

/// Get the private key as bytes
let impl_MLKEM768PrivateKey__as_bytes (self: t_MLKEM768PrivateKey) : t_Array u8 (mk_usize 2400) =
  self._0

/// Create from bytes
let impl_MLKEM768PrivateKey__from_bytes (bytes: t_Array u8 (mk_usize 2400)) : t_MLKEM768PrivateKey =
  MLKEM768PrivateKey bytes <: t_MLKEM768PrivateKey

/// Generate MLKEM-768 keypair from external randomness
/// FOR TEST PURPOSES ONLY
let deterministic_keygen (randomness: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error =
  match
    Core_models.Result.impl__map_err #(Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey)
      #Libcrux_kem.t_Error
      #Anyhow.t_Error
      (Libcrux_kem.key_gen_derand (Libcrux_kem.Algorithm_MlKem768 <: Libcrux_kem.t_Algorithm)
          (randomness <: t_Slice u8)
        <:
        Core_models.Result.t_Result (Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey)
          Libcrux_kem.t_Error)
      (fun e ->
          let e:Libcrux_kem.t_Error = e in
          let args:Libcrux_kem.t_Error = e <: Libcrux_kem.t_Error in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_debug #Libcrux_kem.t_Error args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["MLKEM-768 deterministic key generation failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String))
    <:
    Core_models.Result.t_Result (Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk, pk) ->
    let private_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Libcrux_kem.impl_PrivateKey__encode sk
    in
    let public_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Libcrux_kem.impl_PublicKey__encode pk
    in
    if
      (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global private_key_bytes <: usize) <>.
      v_MLKEM768_PRIVATE_KEY_LEN ||
      (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global public_key_bytes <: usize) <>.
      v_MLKEM768_PUBLIC_KEY_LEN
    then
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
                      (let list = ["Unexpected MLKEM-768 key sizes: private="; ", public="] in
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
      Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error
    else
      (match
          Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 2400))
            #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #Anyhow.t_Error
            (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #(t_Array u8 (mk_usize 2400))
                #FStar.Tactics.Typeclasses.solve
                private_key_bytes
              <:
              Core_models.Result.t_Result (t_Array u8 (mk_usize 2400))
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
          Core_models.Result.t_Result (t_Array u8 (mk_usize 2400)) Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok hoist24 ->
          let private_key:t_MLKEM768PrivateKey = impl_MLKEM768PrivateKey__from_bytes hoist24 in
          (match
              Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 1184))
                #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Anyhow.t_Error
                (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #(t_Array u8 (mk_usize 1184))
                    #FStar.Tactics.Typeclasses.solve
                    public_key_bytes
                  <:
                  Core_models.Result.t_Result (t_Array u8 (mk_usize 1184))
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
              Core_models.Result.t_Result (t_Array u8 (mk_usize 1184)) Anyhow.t_Error
            with
            | Core_models.Result.Result_Ok hoist25 ->
              let public_key:t_MLKEM768PublicKey = impl_MLKEM768PublicKey__from_bytes hoist25 in
              Core_models.Result.Result_Ok
              (private_key, public_key <: (t_MLKEM768PrivateKey & t_MLKEM768PublicKey))
              <:
              Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey)
                Anyhow.t_Error
            | Core_models.Result.Result_Err err ->
              Core_models.Result.Result_Err err
              <:
              Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey)
                Anyhow.t_Error)
        | Core_models.Result.Result_Err err ->
          Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error

/// Generate a new MLKEM-768 keypair using libcrux_kem
let generate_mlkem768_keypair
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error
    ) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result (Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey)
      Libcrux_kem.t_Error) =
    Libcrux_kem.key_gen #v_R (Libcrux_kem.Algorithm_MlKem768 <: Libcrux_kem.t_Algorithm) rng
  in
  let rng:v_R = tmp0 in
  match
    Core_models.Result.impl__map_err #(Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey)
      #Libcrux_kem.t_Error
      #Anyhow.t_Error
      out
      (fun e ->
          let e:Libcrux_kem.t_Error = e in
          let args:Libcrux_kem.t_Error = e <: Libcrux_kem.t_Error in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_debug #Libcrux_kem.t_Error args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["MLKEM-768 key generation failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String))
    <:
    Core_models.Result.t_Result (Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk, pk) ->
    let private_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Libcrux_kem.impl_PrivateKey__encode sk
    in
    let public_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Libcrux_kem.impl_PublicKey__encode pk
    in
    if
      (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global private_key_bytes <: usize) <>.
      v_MLKEM768_PRIVATE_KEY_LEN ||
      (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global public_key_bytes <: usize) <>.
      v_MLKEM768_PUBLIC_KEY_LEN
    then
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
      rng,
      (Core_models.Result.Result_Err
        (Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                        (mk_usize 2)
                        (let list = ["Unexpected MLKEM-768 key sizes: private="; ", public="] in
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
        Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error)
      <:
      (v_R & Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error
      )
    else
      (match
          Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 2400))
            #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #Anyhow.t_Error
            (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #(t_Array u8 (mk_usize 2400))
                #FStar.Tactics.Typeclasses.solve
                private_key_bytes
              <:
              Core_models.Result.t_Result (t_Array u8 (mk_usize 2400))
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
          Core_models.Result.t_Result (t_Array u8 (mk_usize 2400)) Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok hoist29 ->
          let private_key:t_MLKEM768PrivateKey = impl_MLKEM768PrivateKey__from_bytes hoist29 in
          (match
              Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 1184))
                #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Anyhow.t_Error
                (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    #(t_Array u8 (mk_usize 1184))
                    #FStar.Tactics.Typeclasses.solve
                    public_key_bytes
                  <:
                  Core_models.Result.t_Result (t_Array u8 (mk_usize 1184))
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
              Core_models.Result.t_Result (t_Array u8 (mk_usize 1184)) Anyhow.t_Error
            with
            | Core_models.Result.Result_Ok hoist30 ->
              let public_key:t_MLKEM768PublicKey = impl_MLKEM768PublicKey__from_bytes hoist30 in
              let hax_temp_output:Core_models.Result.t_Result
                (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error =
                Core_models.Result.Result_Ok
                (private_key, public_key <: (t_MLKEM768PrivateKey & t_MLKEM768PublicKey))
                <:
                Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey)
                  Anyhow.t_Error
              in
              rng, hax_temp_output
              <:
              (v_R &
                Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey)
                  Anyhow.t_Error)
            | Core_models.Result.Result_Err err ->
              rng,
              (Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey)
                  Anyhow.t_Error)
              <:
              (v_R &
                Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey)
                  Anyhow.t_Error))
        | Core_models.Result.Result_Err err ->
          rng,
          (Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error)
          <:
          (v_R &
            Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error)
      )
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result (t_MLKEM768PrivateKey & t_MLKEM768PublicKey) Anyhow.t_Error)
