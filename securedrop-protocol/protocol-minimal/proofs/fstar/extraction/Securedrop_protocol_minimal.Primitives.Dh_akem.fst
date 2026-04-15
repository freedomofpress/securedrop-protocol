module Securedrop_protocol_minimal.Primitives.Dh_akem
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Hpke_rs in
  let open Libcrux_kem in
  let open Rand_core in
  ()

let v_DH_AKEM_PUBLIC_KEY_LEN: usize = mk_usize 32

let v_DH_AKEM_PRIVATE_KEY_LEN: usize = mk_usize 32

/// An DH-AKEM public key.
type t_DhAkemPublicKey = | DhAkemPublicKey : t_Array u8 (mk_usize 32) -> t_DhAkemPublicKey

let impl_6: Core_models.Clone.t_Clone t_DhAkemPublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// An DH-AKEM private key.
type t_DhAkemPrivateKey = | DhAkemPrivateKey : t_Array u8 (mk_usize 32) -> t_DhAkemPrivateKey

let impl_8: Core_models.Clone.t_Clone t_DhAkemPrivateKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_DhAkemPublicKey__as_bytes (self: t_DhAkemPublicKey) : t_Array u8 (mk_usize 32) = self._0

let impl_DhAkemPublicKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_DhAkemPublicKey =
  DhAkemPublicKey bytes <: t_DhAkemPublicKey

let impl_DhAkemPrivateKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_DhAkemPrivateKey =
  DhAkemPrivateKey bytes <: t_DhAkemPrivateKey

/// Clamp a scalar to ensure it's a valid X25519 scalar.
let clamp (scalar: t_Array u8 (mk_usize 32)) : t_Array u8 (mk_usize 32) =
  let scalar:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize scalar
      (mk_usize 0)
      ((scalar.[ mk_usize 0 ] <: u8) &. mk_u8 248 <: u8)
  in
  let scalar:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize scalar
      (mk_usize 31)
      ((scalar.[ mk_usize 31 ] <: u8) &. mk_u8 127 <: u8)
  in
  let scalar:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_usize scalar
      (mk_usize 31)
      ((scalar.[ mk_usize 31 ] <: u8) |. mk_u8 64 <: u8)
  in
  scalar

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: Core_models.Convert.t_From Hpke_rs.t_HpkePrivateKey t_DhAkemPrivateKey =
  {
    f_from_pre = (fun (sk: t_DhAkemPrivateKey) -> true);
    f_from_post = (fun (sk: t_DhAkemPrivateKey) (out: Hpke_rs.t_HpkePrivateKey) -> true);
    f_from
    =
    fun (sk: t_DhAkemPrivateKey) ->
      Core_models.Convert.f_from #Hpke_rs.t_HpkePrivateKey
        #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        (Alloc.Slice.impl__to_vec #u8 (sk._0 <: t_Slice u8)
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4: Core_models.Convert.t_From Hpke_rs.t_HpkePublicKey t_DhAkemPublicKey =
  {
    f_from_pre = (fun (pk: t_DhAkemPublicKey) -> true);
    f_from_post = (fun (pk: t_DhAkemPublicKey) (out: Hpke_rs.t_HpkePublicKey) -> true);
    f_from
    =
    fun (pk: t_DhAkemPublicKey) ->
      Core_models.Convert.f_from #Hpke_rs.t_HpkePublicKey
        #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        (Alloc.Slice.impl__to_vec #u8 (pk._0 <: t_Slice u8)
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }

/// Helper, convert libcrux type to our key types
let typed (sk: Libcrux_kem.t_PrivateKey) (pk: Libcrux_kem.t_PublicKey)
    : Prims.Pure
      (Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error)
      (requires
        (Alloc.Vec.impl_1__len #u8
            #Alloc.Alloc.t_Global
            (Libcrux_kem.impl_PrivateKey__encode sk <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          <:
          usize) =.
        v_DH_AKEM_PRIVATE_KEY_LEN &&
        (Alloc.Vec.impl_1__len #u8
            #Alloc.Alloc.t_Global
            (Libcrux_kem.impl_PublicKey__encode pk <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          <:
          usize) =.
        v_DH_AKEM_PUBLIC_KEY_LEN)
      (ensures
        fun result ->
          let result:Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey)
            Anyhow.t_Error =
            result
          in
          Core_models.Result.impl__is_ok #(t_DhAkemPrivateKey & t_DhAkemPublicKey)
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
    v_DH_AKEM_PRIVATE_KEY_LEN ||
    (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global public_key_bytes <: usize) <>.
    v_DH_AKEM_PUBLIC_KEY_LEN
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
                    (let list = ["Unexpected DH-AKEM key sizes: private="; ", public="] in
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
    Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error
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
      let private_key:t_DhAkemPrivateKey = impl_DhAkemPrivateKey__from_bytes hoist2 in
      (match
          Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
            #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #Anyhow.t_Error
            (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #(t_Array u8 (mk_usize 32))
                #FStar.Tactics.Typeclasses.solve
                public_key_bytes
              <:
              Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
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
          Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok hoist3 ->
          let public_key:t_DhAkemPublicKey = impl_DhAkemPublicKey__from_bytes hoist3 in
          Core_models.Result.Result_Ok
          (private_key, public_key <: (t_DhAkemPrivateKey & t_DhAkemPublicKey))
          <:
          Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error
        | Core_models.Result.Result_Err err ->
          Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error)
    | Core_models.Result.Result_Err err ->
      Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error

/// Generate DH-AKEM keypair from external randomness
/// FOR TEST PURPOSES ONLY
let deterministic_keygen (randomness: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error =
  let clamped_randomness:t_Array u8 (mk_usize 32) =
    Core_models.Clone.f_clone #(t_Array u8 (mk_usize 32))
      #FStar.Tactics.Typeclasses.solve
      randomness
  in
  let clamped_randomness:t_Array u8 (mk_usize 32) = clamp clamped_randomness in
  match
    Core_models.Result.impl__map_err #(Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey)
      #Libcrux_kem.t_Error
      #Anyhow.t_Error
      (Libcrux_kem.key_gen_derand (Libcrux_kem.Algorithm_X25519 <: Libcrux_kem.t_Algorithm)
          (clamped_randomness <: t_Slice u8)
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
                        (let list = ["DH-AKEM deterministic key generation failed: "] in
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
  | Core_models.Result.Result_Ok (sk, pk) -> typed sk pk
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error

/// Generate a new DH-AKEM key pair using libcrux_kem
let generate_dh_akem_keypair
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result (Libcrux_kem.t_PrivateKey & Libcrux_kem.t_PublicKey)
      Libcrux_kem.t_Error) =
    Libcrux_kem.key_gen #v_R (Libcrux_kem.Algorithm_X25519 <: Libcrux_kem.t_Algorithm) rng
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
                        (let list = ["DH-AKEM key generation failed: "] in
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
    let hax_temp_output:Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey)
      Anyhow.t_Error =
      typed sk pk
    in
    rng, hax_temp_output
    <:
    (v_R & Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result (t_DhAkemPrivateKey & t_DhAkemPublicKey) Anyhow.t_Error)
