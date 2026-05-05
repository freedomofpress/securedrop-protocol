module Securedrop_protocol_minimal.Metadata
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Hpke_rs in
  let open Hpke_rs_crypto in
  let open Hpke_rs_libcrux in
  let open Rand_core in
  let open Securedrop_protocol_minimal.Primitives.Xwing in
  ()

/// The recipient's metadata public key (`pk_R^PKE` in the spec).
type t_MetadataPublicKey =
  | MetadataPublicKey : Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey
    -> t_MetadataPublicKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Fmt.t_Debug t_MetadataPublicKey

unfold
let impl_4 = impl_4'

let impl_5: Core_models.Clone.t_Clone t_MetadataPublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// The recipient's metadata private key (`sk_R^PKE` in the spec).
type t_MetadataPrivateKey =
  | MetadataPrivateKey : Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey
    -> t_MetadataPrivateKey

/// A `(MetadataPrivateKey, MetadataPublicKey)` SD-PKE keypair.
type t_MetadataKeyPair = {
  f_sk:t_MetadataPrivateKey;
  f_pk:t_MetadataPublicKey
}

/// Returns the public key.
let impl_MetadataKeyPair__public_key (self: t_MetadataKeyPair) : t_MetadataPublicKey = self.f_pk

/// Returns the private key.
let impl_MetadataKeyPair__private_key (self: t_MetadataKeyPair) : t_MetadataPrivateKey = self.f_sk

/// SD-PKE ciphertext `(c, c')`: X-Wing encapsulation `c` together with HPKE
/// ciphertext `c'`.
type t_MetadataCiphertext = {
  f_c:t_Array u8 (mk_usize 1120);
  f_cp:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_6': Core_models.Fmt.t_Debug t_MetadataCiphertext

unfold
let impl_6 = impl_6'

let impl_7: Core_models.Clone.t_Clone t_MetadataCiphertext =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Total byte length of the ciphertext: encapsulation `c` + AEAD ciphertext `c'`.
let impl_MetadataCiphertext__len (self: t_MetadataCiphertext) : usize =
  (Core_models.Slice.impl__len #u8 (self.f_c <: t_Slice u8) <: usize) +!
  (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_cp <: usize)

/// SD-PKE.KGen: generate a `MetadataKeyPair`.
/// # Errors
/// Returns an error if X-Wing key generation fails.
let keygen
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error) =
    Securedrop_protocol_minimal.Primitives.Xwing.generate_xwing_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  match
    out
    <:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk_s, pk_s) ->
    let hax_temp_output:Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error =
      Core_models.Result.Result_Ok
      ({
          f_sk = MetadataPrivateKey sk_s <: t_MetadataPrivateKey;
          f_pk = MetadataPublicKey pk_s <: t_MetadataPublicKey
        }
        <:
        t_MetadataKeyPair)
      <:
      Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error
    in
    rng, hax_temp_output <: (v_R & Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error)

/// SD-PKE.KGen (deterministic): derive a `MetadataKeyPair` from 32 bytes of seed material.
/// For use in passphrase-derived key generation only; do not use with random bytes
/// from a live RNG (use [`keygen`] instead).
/// # Errors
/// Returns an error if X-Wing key generation fails.
let deterministic_keygen (randomness: t_Array u8 (mk_usize 32))
    : Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error =
  match
    Securedrop_protocol_minimal.Primitives.Xwing.deterministic_keygen randomness
    <:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk_s, pk_s) ->
    Core_models.Result.Result_Ok
    ({
        f_sk = MetadataPrivateKey sk_s <: t_MetadataPrivateKey;
        f_pk = MetadataPublicKey pk_s <: t_MetadataPublicKey
      }
      <:
      t_MetadataKeyPair)
    <:
    Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result t_MetadataKeyPair Anyhow.t_Error

/// Returns the public key as bytes.
let impl_MetadataPublicKey__as_bytes (self: t_MetadataPublicKey) : t_Slice u8 =
  Securedrop_protocol_minimal.Primitives.Xwing.impl_XWingPublicKey__as_bytes self._0 <: t_Slice u8

/// SD-PKE.Enc: encrypt message `m` to recipient key `pk_r`, returning `(c, c')`.
/// `m` is the sender's serialized long-term APKE public key.
let encrypt (pk_r: t_MetadataPublicKey) (m: t_Slice u8) : t_MetadataCiphertext =
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_Base <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_XWingDraft06 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_Aes256Gcm <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let pk_r_hpke:Hpke_rs.t_HpkePublicKey =
    Core_models.Convert.f_into #Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey
      #Hpke_rs.t_HpkePublicKey
      #FStar.Tactics.Typeclasses.solve
      (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey
          #FStar.Tactics.Typeclasses.solve
          pk_r._0
        <:
        Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPublicKey)
  in
  let
  (tmp0: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux),
  (out:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Hpke_rs.t_HpkeError) =
    Hpke_rs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
      hpke
      pk_r_hpke
      ((let list:Prims.list u8 = [] in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
          Rust_primitives.Hax.array_of_list 0 list)
        <:
        t_Slice u8)
      ((let list:Prims.list u8 = [] in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
          Rust_primitives.Hax.array_of_list 0 list)
        <:
        t_Slice u8)
      m
      (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_None <: Core_models.Option.t_Option Hpke_rs.t_HpkePrivateKey)
  in
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux = tmp0 in
  let
  (c_vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global), (cp: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
    Core_models.Result.impl__expect #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      out
      "SD-PKE encryption failed"
  in
  let (c: t_Array u8 (mk_usize 1120)):t_Array u8 (mk_usize 1120) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 1120))
      #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (Core_models.Convert.f_try_into #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #(t_Array u8 (mk_usize 1120))
          #FStar.Tactics.Typeclasses.solve
          c_vec
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 1120))
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      "X-Wing encapsulation output has unexpected length"
  in
  { f_c = c; f_cp = cp } <: t_MetadataCiphertext

/// SD-PKE.Dec: decrypt `(c, c')` using recipient key `sk_r`, returning message `m`.
/// # Errors
/// Returns an error if HPKE decryption fails.
let decrypt (sk_r: t_MetadataPrivateKey) (ct: t_MetadataCiphertext)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_Base <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_XWingDraft06 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_Aes256Gcm <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let sk_r_hpke:Hpke_rs.t_HpkePrivateKey =
    Core_models.Convert.f_into #Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey
      #Hpke_rs.t_HpkePrivateKey
      #FStar.Tactics.Typeclasses.solve
      (Core_models.Clone.f_clone #Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey
          #FStar.Tactics.Typeclasses.solve
          sk_r._0
        <:
        Securedrop_protocol_minimal.Primitives.Xwing.t_XWingPrivateKey)
  in
  Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #Hpke_rs.t_HpkeError
    #Anyhow.t_Error
    (Hpke_rs.impl_7__open #Hpke_rs_libcrux.t_HpkeLibcrux hpke (ct.f_c <: t_Slice u8) sk_r_hpke
        ((let list:Prims.list u8 = [] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
            Rust_primitives.Hax.array_of_list 0 list)
          <:
          t_Slice u8)
        ((let list:Prims.list u8 = [] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
            Rust_primitives.Hax.array_of_list 0 list)
          <:
          t_Slice u8)
        (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            ct.f_cp
          <:
          t_Slice u8) (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
        (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
        (Core_models.Option.Option_None <: Core_models.Option.t_Option Hpke_rs.t_HpkePublicKey)
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
                      (let list = ["SD-PKE decryption failed: "] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                      args
                    <:
                    Core_models.Fmt.t_Arguments)
                <:
                Alloc.String.t_String)
            <:
            Alloc.String.t_String))
