module Securedrop_protocol_minimal.Message
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Hpke_rs in
  let open Hpke_rs_crypto in
  let open Hpke_rs_libcrux in
  let open Libcrux_ml_kem.Mlkem768 in
  let open Libcrux_traits.Kem.Arrayref in
  let open Libcrux_traits.Kem.Owned in
  let open Rand_core in
  let open Securedrop_protocol_minimal.Primitives.Dh_akem in
  ()

let v_PSK_ID: t_Slice u8 =
  (let list =
      [
        mk_u8 83; mk_u8 68; mk_u8 45; mk_u8 112; mk_u8 115; mk_u8 107; mk_u8 65; mk_u8 80; mk_u8 75;
        mk_u8 69
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 10);
    Rust_primitives.Hax.array_of_list 10 list)
  <:
  t_Slice u8

let v_LEN_MLKEM_ENCAPS_RAND: usize = mk_usize 32

/// The SD-APKE public key tuple `pk^APKE = (pk1, pk2)`.
/// - `pk1`: DHKEM(X25519) component (`pk^AKEM`)
/// - `pk2`: ML-KEM-768 component (`pk^PQ`)
type t_MessagePublicKey = {
  f_dhakem:Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_mlkem:Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Fmt.t_Debug t_MessagePublicKey

unfold
let impl_3 = impl_3'

let impl_4: Core_models.Clone.t_Clone t_MessagePublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// The SD-APKE private key tuple `sk^APKE = (sk1, sk2)`.
/// - `sk1`: DHKEM(X25519) component (`sk^AKEM`)
/// - `sk2`: ML-KEM-768 component (`sk^PQ`)
type t_MessagePrivateKey = {
  f_dhakem:Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey;
  f_mlkem:Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PrivateKey
}

/// A `(MessagePrivateKey, MessagePublicKey)` SD-APKE keypair.
type t_MessageKeyPair = {
  f_sk:t_MessagePrivateKey;
  f_pk:t_MessagePublicKey
}

/// Returns the public key.
let impl_MessageKeyPair__public_key (self: t_MessageKeyPair) : t_MessagePublicKey = self.f_pk

/// Returns the private key.
let impl_MessageKeyPair__private_key (self: t_MessageKeyPair) : t_MessagePrivateKey = self.f_sk

/// Serialize the key tuple in canonical byte order: `pk1 || pk2`.
let impl_MessagePublicKey__as_bytes (self: t_MessagePublicKey)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Securedrop_protocol_minimal.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes self.f_dhakem
        <:
        t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes self.f_mlkem
        <:
        t_Slice u8)
  in
  out

/// Deserialize from `pk1 || pk2` bytes.
/// # Errors
/// Returns an error if the byte slice has incorrect length.
let impl_MessagePublicKey__from_bytes (bytes: t_Slice u8)
    : Core_models.Result.t_Result t_MessagePublicKey Anyhow.t_Error =
  if
    (Core_models.Slice.impl__len #u8 bytes <: usize) <>.
    (Securedrop_protocol_minimal.Primitives.Dh_akem.v_DH_AKEM_PUBLIC_KEY_LEN +!
      Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PUBLIC_KEY_LEN
      <:
      usize)
  then
    let args:(usize & usize) =
      Securedrop_protocol_minimal.Primitives.Dh_akem.v_DH_AKEM_PUBLIC_KEY_LEN +!
      Securedrop_protocol_minimal.Primitives.Mlkem.v_MLKEM768_PUBLIC_KEY_LEN,
      Core_models.Slice.impl__len #u8 bytes
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
                    (let list = ["Invalid MessagePublicKey length: expected "; ", got "] in
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
    Core_models.Result.t_Result t_MessagePublicKey Anyhow.t_Error
  else
    let (dhakem_bytes: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
      Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
        #Core_models.Array.t_TryFromSliceError
        (Core_models.Convert.f_try_into #(t_Slice u8)
            #(t_Array u8 (mk_usize 32))
            #FStar.Tactics.Typeclasses.solve
            (bytes.[ {
                  Core_models.Ops.Range.f_end
                  =
                  Securedrop_protocol_minimal.Primitives.Dh_akem.v_DH_AKEM_PUBLIC_KEY_LEN
                }
                <:
                Core_models.Ops.Range.t_RangeTo usize ]
              <:
              t_Slice u8)
          <:
          Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
            Core_models.Array.t_TryFromSliceError)
        "checked length"
    in
    let (mlkem_bytes: t_Array u8 (mk_usize 1184)):t_Array u8 (mk_usize 1184) =
      Core_models.Result.impl__expect #(t_Array u8 (mk_usize 1184))
        #Core_models.Array.t_TryFromSliceError
        (Core_models.Convert.f_try_into #(t_Slice u8)
            #(t_Array u8 (mk_usize 1184))
            #FStar.Tactics.Typeclasses.solve
            (bytes.[ {
                  Core_models.Ops.Range.f_start
                  =
                  Securedrop_protocol_minimal.Primitives.Dh_akem.v_DH_AKEM_PUBLIC_KEY_LEN
                }
                <:
                Core_models.Ops.Range.t_RangeFrom usize ]
              <:
              t_Slice u8)
          <:
          Core_models.Result.t_Result (t_Array u8 (mk_usize 1184))
            Core_models.Array.t_TryFromSliceError)
        "checked length"
    in
    Core_models.Result.Result_Ok
    ({
        f_dhakem
        =
        Securedrop_protocol_minimal.Primitives.Dh_akem.impl_DhAkemPublicKey__from_bytes dhakem_bytes;
        f_mlkem
        =
        Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PublicKey__from_bytes mlkem_bytes
      }
      <:
      t_MessagePublicKey)
    <:
    Core_models.Result.t_Result t_MessagePublicKey Anyhow.t_Error

/// SD-APKE ciphertext `((c1, cp), c2)`.
type t_MessageCiphertext = {
  f_c1:t_Array u8 (mk_usize 32);
  f_cp:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_c2:t_Array u8 (mk_usize 1088)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_MessageCiphertext

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_MessageCiphertext =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Total byte length: `c1 + cp + c2`.
let impl_MessageCiphertext__len (self: t_MessageCiphertext) : usize =
  ((Core_models.Slice.impl__len #u8 (self.f_c1 <: t_Slice u8) <: usize) +!
    (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_cp <: usize)
    <:
    usize) +!
  (Core_models.Slice.impl__len #u8 (self.f_c2 <: t_Slice u8) <: usize)

/// SD-APKE.KGen: generate a `MessageKeyPair`.
/// # Errors
/// Returns an error if key generation fails.
let keygen
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error) =
    Securedrop_protocol_minimal.Primitives.Dh_akem.generate_dh_akem_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  match
    out
    <:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk1, pk1) ->
    let
    (tmp0: v_R),
    (out:
      Core_models.Result.t_Result
        (Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PrivateKey &
          Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PublicKey) Anyhow.t_Error) =
      Securedrop_protocol_minimal.Primitives.Mlkem.generate_mlkem768_keypair #v_R rng
    in
    let rng:v_R = tmp0 in
    (match
        out
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PrivateKey &
            Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PublicKey) Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok (sk2, pk2) ->
        let hax_temp_output:Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error =
          Core_models.Result.Result_Ok
          ({
              f_sk = { f_dhakem = sk1; f_mlkem = sk2 } <: t_MessagePrivateKey;
              f_pk = { f_dhakem = pk1; f_mlkem = pk2 } <: t_MessagePublicKey
            }
            <:
            t_MessageKeyPair)
          <:
          Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error
        in
        rng, hax_temp_output <: (v_R & Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        rng,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error)
        <:
        (v_R & Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error)

/// SD-APKE.KGen (deterministic): derive a `MessageKeyPair` from seed material.
/// For use in passphrase-derived key generation only.
let deterministic_keygen (dh_seed: t_Array u8 (mk_usize 32)) (mlkem_seed: t_Array u8 (mk_usize 64))
    : Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error =
  match
    Securedrop_protocol_minimal.Primitives.Dh_akem.deterministic_keygen dh_seed
    <:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk1, pk1) ->
    (match
        Securedrop_protocol_minimal.Primitives.Mlkem.deterministic_keygen mlkem_seed
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PrivateKey &
            Securedrop_protocol_minimal.Primitives.Mlkem.t_MLKEM768PublicKey) Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok (sk2, pk2) ->
        Core_models.Result.Result_Ok
        ({
            f_sk = { f_dhakem = sk1; f_mlkem = sk2 } <: t_MessagePrivateKey;
            f_pk = { f_dhakem = pk1; f_mlkem = pk2 } <: t_MessagePublicKey
          }
          <:
          t_MessageKeyPair)
        <:
        Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_MessageKeyPair Anyhow.t_Error

/// SD-APKE.AuthEnc: encrypt message `m` from sender to recipient.
/// - `sk = (skS1, skS2)`: sender's SD-APKE private key
/// - `pk = (pkR1, pkR2)`: recipient's SD-APKE public key
/// - `ad`: associated data
/// - `info`: caller-supplied info (spec prepends `c2` internally: `info = c2 + info`)
/// # Errors
/// Returns an error if ML-KEM encapsulation or HPKE sealing fails.
let auth_enc
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (sk: t_MessagePrivateKey)
      (pk: t_MessagePublicKey)
      (m ad info: t_Slice u8)
    : (v_R & Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error) =
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_AuthPsk <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_DhKem25519 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_Aes256Gcm <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let randomness:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng randomness
  in
  let rng:v_R = tmp0 in
  let randomness:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  match
    Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 1088))
      #Libcrux_traits.Kem.Arrayref.t_EncapsError
      #Anyhow.t_Error
      (Libcrux_traits.Kem.Owned.f_encaps #Libcrux_ml_kem.Mlkem768.t_MlKem768 #(mk_usize 1184)
          #(mk_usize 2400) #(mk_usize 1088) #(mk_usize 32) #(mk_usize 64) #(mk_usize 32)
          #FStar.Tactics.Typeclasses.solve
          (Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes pk.f_mlkem
            <:
            t_Array u8 (mk_usize 1184)) randomness
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 1088))
          Libcrux_traits.Kem.Arrayref.t_EncapsError)
      (fun e ->
          let e:Libcrux_traits.Kem.Arrayref.t_EncapsError = e in
          let args:Libcrux_traits.Kem.Arrayref.t_EncapsError =
            e <: Libcrux_traits.Kem.Arrayref.t_EncapsError
          in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list =
              [Core_models.Fmt.Rt.impl__new_debug #Libcrux_traits.Kem.Arrayref.t_EncapsError args]
            in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["ML-KEM encapsulation failed: "] in
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
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 1088))
      Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (k2, c2) ->
    let (pkr1: Hpke_rs.t_HpkePublicKey):Hpke_rs.t_HpkePublicKey =
      Core_models.Convert.f_into #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey
        #Hpke_rs.t_HpkePublicKey
        #FStar.Tactics.Typeclasses.solve
        (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey
            #FStar.Tactics.Typeclasses.solve
            pk.f_dhakem
          <:
          Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey)
    in
    let (sks1: Hpke_rs.t_HpkePrivateKey):Hpke_rs.t_HpkePrivateKey =
      Core_models.Convert.f_into #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey
        #Hpke_rs.t_HpkePrivateKey
        #FStar.Tactics.Typeclasses.solve
        (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey
            #FStar.Tactics.Typeclasses.solve
            sk.f_dhakem
          <:
          Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey)
    in
    let full_info:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
    let full_info:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global full_info (c2 <: t_Slice u8)
    in
    let full_info:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global full_info info
    in
    let
    (tmp0: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux),
    (out:
      Core_models.Result.t_Result
        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Hpke_rs.t_HpkeError) =
      Hpke_rs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
        hpke
        pkr1
        (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            full_info
          <:
          t_Slice u8)
        ad
        m
        (Core_models.Option.Option_Some (k2 <: t_Slice u8)
          <:
          Core_models.Option.t_Option (t_Slice u8))
        (Core_models.Option.Option_Some v_PSK_ID <: Core_models.Option.t_Option (t_Slice u8))
        (Core_models.Option.Option_Some sks1 <: Core_models.Option.t_Option Hpke_rs.t_HpkePrivateKey
        )
    in
    let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux = tmp0 in
    (match
        Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #Hpke_rs.t_HpkeError
          #Anyhow.t_Error
          out
          (fun e ->
              let e:Hpke_rs.t_HpkeError = e in
              let args:Hpke_rs.t_HpkeError = e <: Hpke_rs.t_HpkeError in
              let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                let list = [Core_models.Fmt.Rt.impl__new_debug #Hpke_rs.t_HpkeError args] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list
              in
              Anyhow.Error.impl__msg #Alloc.String.t_String
                (Core_models.Hint.must_use #Alloc.String.t_String
                    (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                            (mk_usize 1)
                            (let list = ["SD-APKE AuthEnc failed: "] in
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
        Core_models.Result.t_Result
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok (c1_vec, cp) ->
        let (c1: t_Array u8 (mk_usize 32)):t_Array u8 (mk_usize 32) =
          Core_models.Result.impl__expect #(t_Array u8 (mk_usize 32))
            #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #(t_Array u8 (mk_usize 32))
                #FStar.Tactics.Typeclasses.solve
                c1_vec
              <:
              Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
                (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            "DHKEM(X25519) encapsulation output has unexpected length"
        in
        let hax_temp_output:Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error =
          Core_models.Result.Result_Ok ({ f_c1 = c1; f_cp = cp; f_c2 = c2 } <: t_MessageCiphertext)
          <:
          Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error
        in
        rng, hax_temp_output
        <:
        (v_R & Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        rng,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error)
        <:
        (v_R & Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error))
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result t_MessageCiphertext Anyhow.t_Error)

/// SD-APKE.AuthDec: decrypt ciphertext from sender.
/// - `sk = (skR1, skR2)`: recipient's SD-APKE private key
/// - `pk = (pkS1, pkS2)`: sender's SD-APKE public key
/// - `ad`: associated data
/// - `info`: caller-supplied info (spec prepends `c2` internally: `info = c2 + info`)
/// # Errors
/// Returns an error if ML-KEM decapsulation or HPKE opening fails.
let auth_dec
      (sk: t_MessagePrivateKey)
      (pk: t_MessagePublicKey)
      (ct: t_MessageCiphertext)
      (ad info: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_AuthPsk <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_DhKem25519 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_Aes256Gcm <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  match
    Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
      #Libcrux_traits.Kem.Arrayref.t_DecapsError
      #Anyhow.t_Error
      (Libcrux_traits.Kem.Owned.f_decaps #Libcrux_ml_kem.Mlkem768.t_MlKem768 #(mk_usize 1184)
          #(mk_usize 2400) #(mk_usize 1088) #(mk_usize 32) #(mk_usize 64) #(mk_usize 32)
          #FStar.Tactics.Typeclasses.solve ct.f_c2
          (Securedrop_protocol_minimal.Primitives.Mlkem.impl_MLKEM768PrivateKey__as_bytes sk.f_mlkem
            <:
            t_Array u8 (mk_usize 2400))
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
          Libcrux_traits.Kem.Arrayref.t_DecapsError)
      (fun e ->
          let e:Libcrux_traits.Kem.Arrayref.t_DecapsError = e in
          let args:Libcrux_traits.Kem.Arrayref.t_DecapsError =
            e <: Libcrux_traits.Kem.Arrayref.t_DecapsError
          in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list =
              [Core_models.Fmt.Rt.impl__new_debug #Libcrux_traits.Kem.Arrayref.t_DecapsError args]
            in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["ML-KEM decapsulation failed: "] in
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
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok k2 ->
    let (skr1: Hpke_rs.t_HpkePrivateKey):Hpke_rs.t_HpkePrivateKey =
      Core_models.Convert.f_into #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey
        #Hpke_rs.t_HpkePrivateKey
        #FStar.Tactics.Typeclasses.solve
        (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey
            #FStar.Tactics.Typeclasses.solve
            sk.f_dhakem
          <:
          Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPrivateKey)
    in
    let (pks1: Hpke_rs.t_HpkePublicKey):Hpke_rs.t_HpkePublicKey =
      Core_models.Convert.f_into #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey
        #Hpke_rs.t_HpkePublicKey
        #FStar.Tactics.Typeclasses.solve
        (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey
            #FStar.Tactics.Typeclasses.solve
            pk.f_dhakem
          <:
          Securedrop_protocol_minimal.Primitives.Dh_akem.t_DhAkemPublicKey)
    in
    let full_info:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
    let full_info:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8
        #Alloc.Alloc.t_Global
        full_info
        (ct.f_c2 <: t_Slice u8)
    in
    let full_info:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global full_info info
    in
    Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      #Anyhow.t_Error
      (Hpke_rs.impl_7__open #Hpke_rs_libcrux.t_HpkeLibcrux hpke (ct.f_c1 <: t_Slice u8) skr1
          (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              full_info
            <:
            t_Slice u8) ad
          (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              ct.f_cp
            <:
            t_Slice u8)
          (Core_models.Option.Option_Some (k2 <: t_Slice u8)
            <:
            Core_models.Option.t_Option (t_Slice u8))
          (Core_models.Option.Option_Some v_PSK_ID <: Core_models.Option.t_Option (t_Slice u8))
          (Core_models.Option.Option_Some pks1
            <:
            Core_models.Option.t_Option Hpke_rs.t_HpkePublicKey)
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Hpke_rs.t_HpkeError)
      (fun e ->
          let e:Hpke_rs.t_HpkeError = e in
          let args:Hpke_rs.t_HpkeError = e <: Hpke_rs.t_HpkeError in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_debug #Hpke_rs.t_HpkeError args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["SD-APKE AuthDec failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String))
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
